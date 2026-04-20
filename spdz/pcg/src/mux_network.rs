//! Application-level network multiplexer.
//!
//! Wraps a single underlying [`Network`] and exposes it as N
//! independent logical [`Network`]s. Each logical network tags its
//! outgoing messages with a stream-id prefix; a background router
//! thread demultiplexes incoming messages into per-stream queues so
//! each logical `recv` only sees its own stream's traffic.
//!
//! ## Use case
//!
//! For oblivious DPF gen's parallel cross-term DMPF generation: each of the 4
//! cross-terms wants its own independent network channel. With a
//! native QUIC connection, you could use [`QuicNetwork::fork`] which
//! opens new bidirectional QUIC streams over the same socket. With
//! any other transport (LocalNetwork in tests, TCP, etc.), this
//! application-level multiplexer provides the same parallelism without
//! requiring transport-specific support.
//!
//! ## Wire format
//!
//! Each multiplexed message is `[stream_id: u32 BE][payload: bytes...]`.
//! Both parties run their own multiplexer with matching `n_streams`,
//! so stream IDs align across the wire.
//!
//! ## Concurrency
//!
//! - **Sends**: thread-safe per logical network (multiple threads can
//!   send concurrently because `Network::send` takes `&self`). The
//!   underlying transport must be thread-safe (LocalNetwork uses
//!   crossbeam channels, QUIC uses async streams under a mutex).
//! - **Receives**: a single router thread reads from the underlying
//!   transport in a tight loop, demultiplexing by stream-id. Per-stream
//!   queues are guarded by `Mutex<VecDeque<_>>` + `Condvar` for blocking
//!   `recv`.
//!
//! ## Limitations
//!
//! - 2-party only (uses peer_id = 1 - my_id). Generalizing to N-party
//!   would multiplex per-pair queues.
//! - Router thread runs until the underlying transport's recv errors
//!   (e.g., on connection close). Clean shutdown via a sentinel stream
//!   id is a follow-up.

#![cfg(feature = "gc")]

use eyre::Result;
use mpc_net::{ConnectionStats, Network};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(60);

/// One logical network multiplexed over a shared underlying transport.
pub struct MuxNetwork<N: Network + Send + Sync + 'static> {
    inner: Arc<N>,
    stream_id: u32,
    /// Per-stream incoming queue (filled by the shared router thread,
    /// drained by this logical network's `recv` calls).
    incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
    incoming_cond: Arc<Condvar>,
    /// Bookkeeping for `get_connection_stats`.
    sent_bytes: Arc<AtomicUsize>,
    recv_bytes: Arc<AtomicUsize>,
    /// Receive timeout for blocking `recv`.
    timeout: Duration,
}

impl<N: Network + Send + Sync + 'static> MuxNetwork<N> {
    /// Create `n_streams` independent logical networks multiplexed over
    /// `inner`. Spawns a background router thread; both parties must
    /// call this with matching `n_streams` so stream-id assignments
    /// agree.
    pub fn new(inner: Arc<N>, n_streams: usize) -> Vec<Self> {
        Self::with_timeout(inner, n_streams, DEFAULT_RECV_TIMEOUT)
    }

    /// Same as [`Self::new`] but with a configurable per-`recv` timeout.
    pub fn with_timeout(inner: Arc<N>, n_streams: usize, timeout: Duration) -> Vec<Self> {
        let my_id = inner.id();
        // 2-party assumption.
        assert!(my_id == 0 || my_id == 1, "MuxNetwork only supports 2-party");
        let peer_id = 1 - my_id;

        let queues: Vec<Arc<Mutex<VecDeque<Vec<u8>>>>> =
            (0..n_streams).map(|_| Arc::new(Mutex::new(VecDeque::new()))).collect();
        let conds: Vec<Arc<Condvar>> = (0..n_streams).map(|_| Arc::new(Condvar::new())).collect();
        let sent_bytes: Vec<Arc<AtomicUsize>> =
            (0..n_streams).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let recv_bytes: Vec<Arc<AtomicUsize>> =
            (0..n_streams).map(|_| Arc::new(AtomicUsize::new(0))).collect();

        // Spawn the router thread.
        let inner_router = inner.clone();
        let queues_router = queues.clone();
        let conds_router = conds.clone();
        let recv_bytes_router = recv_bytes.clone();
        std::thread::spawn(move || loop {
            match inner_router.recv(peer_id) {
                Ok(msg) if msg.len() >= 4 => {
                    let stream_id =
                        u32::from_be_bytes(msg[..4].try_into().expect("just checked length"));
                    let payload = msg[4..].to_vec();
                    let idx = stream_id as usize;
                    if idx >= queues_router.len() {
                        // Drop messages with unknown stream IDs (should
                        // never happen if both parties agree on
                        // n_streams).
                        continue;
                    }
                    recv_bytes_router[idx].fetch_add(payload.len(), Ordering::Relaxed);
                    {
                        let mut q = queues_router[idx].lock().unwrap();
                        q.push_back(payload);
                    }
                    conds_router[idx].notify_one();
                }
                Ok(_) => {
                    // Malformed (too short) — ignore.
                    continue;
                }
                Err(_) => {
                    // Underlying transport error / closed — exit
                    // router. Outstanding `recv` calls on logical
                    // streams will time out.
                    break;
                }
            }
        });

        (0..n_streams)
            .map(|i| MuxNetwork {
                inner: inner.clone(),
                stream_id: i as u32,
                incoming: queues[i].clone(),
                incoming_cond: conds[i].clone(),
                sent_bytes: sent_bytes[i].clone(),
                recv_bytes: recv_bytes[i].clone(),
                timeout,
            })
            .collect()
    }
}

impl<N: Network + Send + Sync + 'static> Network for MuxNetwork<N> {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: &[u8]) -> Result<()> {
        let mut tagged = Vec::with_capacity(data.len() + 4);
        tagged.extend_from_slice(&self.stream_id.to_be_bytes());
        tagged.extend_from_slice(data);
        self.sent_bytes.fetch_add(data.len(), Ordering::Relaxed);
        self.inner.send(to, &tagged)
    }

    fn recv(&self, _from: usize) -> Result<Vec<u8>> {
        let mut q = self.incoming.lock().unwrap();
        loop {
            if let Some(data) = q.pop_front() {
                return Ok(data);
            }
            // Wait for the router thread to push to our queue.
            let (q2, timeout_result) =
                self.incoming_cond.wait_timeout(q, self.timeout).unwrap();
            q = q2;
            if timeout_result.timed_out() && q.is_empty() {
                eyre::bail!("MuxNetwork::recv timed out (stream {})", self.stream_id);
            }
        }
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let peer_id = 1 - self.inner.id();
        let mut stats = BTreeMap::new();
        stats.insert(
            peer_id,
            (
                self.sent_bytes.load(Ordering::Relaxed),
                self.recv_bytes.load(Ordering::Relaxed),
            ),
        );
        ConnectionStats::new(self.inner.id(), stats)
    }
}
