//! Production-grade `BitOt` backed by mpz's Ferret silent OT.
//!
//! Implements `pcg_protocols::BitOt` by converting Ferret's RCOT (random
//! correlated OT) into chosen-message bit / block OT via derandomization.
//!
//! ## Protocol
//!
//! An RCOT gives:
//!   - **Sender**: keys `K_i`, global correlation `Δ`. Implicit messages
//!     `(K_i, K_i ⊕ Δ)`.
//!   - **Receiver**: a random choice bit `b_i`, message `M_i = K_i ⊕ b_i·Δ`.
//!
//! To send chosen messages `(m_0, m_1)` with receiver choice `c`:
//!
//! 1. Receiver sends `d = b_i ⊕ c` to sender (1 bit per OT).
//! 2. Sender hashes `h_0 = H(K_i)`, `h_1 = H(K_i ⊕ Δ)` and sends
//!    `(m_0 ⊕ h_d, m_1 ⊕ h_{1 ⊕ d})`.
//! 3. Receiver computes `h = H(M_i)` and decrypts the `c`-th ciphertext. The
//!    algebraic identity `H(K_{c ⊕ d}) = H(K_{b_i}) = H(M_i)` means exactly
//!    the `c`-th slot decrypts to `m_c`.
//!
//! Communication: 1 bit (derandomization) + 2·|m| bits (ciphertexts) per call.
//!
//! ## Pool management
//!
//! Each party holds:
//!   - A **sender pool** of `K_i` blocks (used when this party acts as OT sender)
//!   - A **receiver pool** of `(b_i, M_i)` tuples (used when this party acts
//!     as OT receiver)
//!
//! Both pools are pre-populated on `new()`. They refill lazily when drained.
//! mpz's Ferret RCOT supports incremental `alloc + flush`, so refills just
//! extend the pool.
//!
//! ## Initialization ordering
//!
//! Two Ferret flushes (one per direction) happen on `new()`. To avoid
//! deadlocking between `P0.sender ↔ P1.receiver` and `P1.sender ↔ P0.receiver`,
//! parties call the prepares in opposite orders, driven by party id.

use eyre::Result;
use mpc_net::Network;
use mpz_core::Block as MpzBlock;
use pcg_protocols::{BitOt, Block as BitOtBlock};
use sha3::{Digest, Sha3_256};
use spdz_core::ot::ferret::FerretSession;
use std::sync::Arc;

/// Default RCOT pool size per direction (bit-OT + block-OT share the pool).
const DEFAULT_POOL_SIZE: usize = 65536;

/// Pool of RCOTs that we consume one-at-a-time.
struct SenderPool {
    /// Keys `K_i` ready to be consumed.
    keys: Vec<MpzBlock>,
    /// Next index to consume (front of the unread queue).
    next: usize,
    /// Monotonic counter across all RCOTs ever consumed; used for hash domain
    /// separation.
    global_counter: u64,
}

struct ReceiverPool {
    /// Random choices `b_i`.
    choices: Vec<bool>,
    /// Messages `M_i = K_i ⊕ b_i·Δ`.
    msgs: Vec<MpzBlock>,
    /// Next index to consume.
    next: usize,
    /// Monotonic counter matching the peer's sender `global_counter`.
    global_counter: u64,
}

/// Bit OT backed by Ferret silent OT.
///
/// Wraps a `FerretSession` and exposes the symmetric `BitOt` trait required
/// by `pcg-protocols` primitives (`sec_and`, `sec_and_block`, `a2b_convert`,
/// `mul_to_add_share`).
pub struct FerretBitOt<N: Network + Unpin + 'static> {
    session: FerretSession<N>,
    net: Arc<N>,
    my_id: usize,
    peer_id: usize,
    delta: MpzBlock,
    sender_pool: SenderPool,
    receiver_pool: ReceiverPool,
    /// Pool size used for the initial prepare and every refill.
    pool_size: usize,
}

impl<N: Network + Unpin + 'static> FerretBitOt<N> {
    /// Create a new `FerretBitOt`. Both parties must call this; it performs the
    /// Ferret initialization and pre-prepares one pool of each direction.
    pub fn new(net: Arc<N>) -> Result<Self> {
        Self::with_pool_size(net, DEFAULT_POOL_SIZE)
    }

    /// Same as [`Self::new`] but with a configurable pool size.
    pub fn with_pool_size(net: Arc<N>, pool_size: usize) -> Result<Self> {
        let my_id = net.id();
        if my_id > 1 {
            eyre::bail!("FerretBitOt only supports 2-party (got id {my_id})");
        }
        let peer_id = 1 - my_id;

        let mut session = FerretSession::new(net.clone())?;

        // Two Ferret flushes are needed, one per direction. We alternate the
        // order by party id to avoid deadlocking the synchronous channel
        // (each flush is sync-serialized through the shared async context).
        let (delta, sender_out, receiver_out) = if my_id == 0 {
            // Phase 1: P0.sender ↔ P1.receiver
            let delta = session.prepare_sender(pool_size)?;
            let keys = session.consume_sender(pool_size)?;
            // Phase 2: P1.sender ↔ P0.receiver
            session.prepare_receiver(pool_size)?;
            let (choices, msgs) = session.consume_receiver(pool_size)?;
            (delta, keys, (choices, msgs))
        } else {
            // Phase 1: P0.sender ↔ P1.receiver
            session.prepare_receiver(pool_size)?;
            let (choices, msgs) = session.consume_receiver(pool_size)?;
            // Phase 2: P1.sender ↔ P0.receiver
            let delta = session.prepare_sender(pool_size)?;
            let keys = session.consume_sender(pool_size)?;
            (delta, keys, (choices, msgs))
        };

        let sender_pool = SenderPool {
            keys: sender_out,
            next: 0,
            global_counter: 0,
        };
        let receiver_pool = ReceiverPool {
            choices: receiver_out.0,
            msgs: receiver_out.1,
            next: 0,
            global_counter: 0,
        };

        Ok(Self {
            session,
            net,
            my_id,
            peer_id,
            delta,
            sender_pool,
            receiver_pool,
            pool_size,
        })
    }

    /// Pop one RCOT sender key from the pool, refilling if empty.
    fn pop_sender(&mut self) -> Result<(MpzBlock, u64)> {
        if self.sender_pool.next >= self.sender_pool.keys.len() {
            self.refill_sender()?;
        }
        let key = self.sender_pool.keys[self.sender_pool.next];
        self.sender_pool.next += 1;
        let ctr = self.sender_pool.global_counter;
        self.sender_pool.global_counter += 1;
        Ok((key, ctr))
    }

    /// Pop one RCOT receiver `(b, M)` from the pool, refilling if empty.
    fn pop_receiver(&mut self) -> Result<(bool, MpzBlock, u64)> {
        if self.receiver_pool.next >= self.receiver_pool.choices.len() {
            self.refill_receiver()?;
        }
        let i = self.receiver_pool.next;
        let b = self.receiver_pool.choices[i];
        let m = self.receiver_pool.msgs[i];
        self.receiver_pool.next += 1;
        let ctr = self.receiver_pool.global_counter;
        self.receiver_pool.global_counter += 1;
        Ok((b, m, ctr))
    }

    fn refill_sender(&mut self) -> Result<()> {
        // Refill is a single flush in the direction self.sender ↔ peer.receiver.
        // Because bool2pc primitives run in lock-step, the peer's receiver pool
        // drains symmetrically and the peer will call `refill_receiver` at the
        // matching moment. Ordering therefore does not require id-based swap.
        let _delta = self.session.prepare_sender(self.pool_size)?;
        let keys = self.session.consume_sender(self.pool_size)?;
        self.sender_pool.keys = keys;
        self.sender_pool.next = 0;
        Ok(())
    }

    fn refill_receiver(&mut self) -> Result<()> {
        self.session.prepare_receiver(self.pool_size)?;
        let (choices, msgs) = self.session.consume_receiver(self.pool_size)?;
        self.receiver_pool.choices = choices;
        self.receiver_pool.msgs = msgs;
        self.receiver_pool.next = 0;
        Ok(())
    }

    /// Send a payload to the peer.
    fn net_send(&self, data: &[u8]) -> Result<()> {
        self.net
            .send(self.peer_id, data)
            .map_err(|e| eyre::eyre!("net send: {e}"))
    }

    /// Receive a payload from the peer.
    fn net_recv(&self) -> Result<Vec<u8>> {
        self.net
            .recv(self.peer_id)
            .map_err(|e| eyre::eyre!("net recv: {e}"))
    }
}

// ─────────────────────────── hash helpers ─────────────────────────── //

/// Correlation-robust hash of an RCOT key/msg block to a 16-byte block.
///
/// Domain separation: `(rcot_sender_id, counter)` uniquely identifies an
/// RCOT. `rcot_sender_id` distinguishes direction so the two pools never
/// collide.
fn hash_to_block(key: MpzBlock, rcot_sender_id: usize, counter: u64) -> [u8; 16] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"FERRET-BITOT-BLOCK\x00");
    hasher.update((rcot_sender_id as u64).to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Correlation-robust hash of an RCOT key/msg block to a single bit.
/// Uses a DIFFERENT domain tag than `hash_to_block` so the two cannot be
/// correlated against each other.
fn hash_to_bit(key: MpzBlock, rcot_sender_id: usize, counter: u64) -> bool {
    let mut hasher = Sha3_256::new();
    hasher.update(b"FERRET-BITOT-BIT\x00");
    hasher.update((rcot_sender_id as u64).to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    digest[0] & 1 == 1
}

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

// ─────────────────────────── BitOt impl ─────────────────────────── //

impl<N: Network + Unpin + 'static> BitOt for FerretBitOt<N> {
    fn send_bit(&mut self, m_0: bool, m_1: bool) -> Result<()> {
        let (key, ctr) = self.pop_sender()?;
        // Receive derandomization bit d from receiver.
        let d_buf = self.net_recv()?;
        if d_buf.is_empty() {
            eyre::bail!("send_bit: empty derandomization msg");
        }
        let d = d_buf[0] & 1 == 1;

        // h_0 = H(K_i), h_1 = H(K_i ⊕ Δ)
        let key_xor_delta = key ^ self.delta;
        let h_0 = hash_to_bit(key, self.my_id, ctr);
        let h_1 = hash_to_bit(key_xor_delta, self.my_id, ctr);

        // Ciphertexts: c_0 = m_0 ⊕ h_d, c_1 = m_1 ⊕ h_{1⊕d}.
        let (hc0, hc1) = if d { (h_1, h_0) } else { (h_0, h_1) };
        let c_0 = m_0 ^ hc0;
        let c_1 = m_1 ^ hc1;
        let packed = ((c_0 as u8) & 1) | (((c_1 as u8) & 1) << 1);
        self.net_send(&[packed])?;
        Ok(())
    }

    fn recv_bit(&mut self, choice: bool) -> Result<bool> {
        let (b, m, ctr) = self.pop_receiver()?;
        // Send derandomization d = b ⊕ choice.
        let d = b ^ choice;
        self.net_send(&[d as u8])?;

        // Receive ciphertexts.
        let buf = self.net_recv()?;
        if buf.is_empty() {
            eyre::bail!("recv_bit: empty ciphertext msg");
        }
        let c_0 = buf[0] & 1 == 1;
        let c_1 = (buf[0] >> 1) & 1 == 1;
        let c_c = if choice { c_1 } else { c_0 };

        // Decrypt with h = H(M). Note: peer's `rcot_sender_id` = peer_id.
        let h = hash_to_bit(m, self.peer_id, ctr);
        Ok(c_c ^ h)
    }

    fn send_block(&mut self, m_0: BitOtBlock, m_1: BitOtBlock) -> Result<()> {
        let (key, ctr) = self.pop_sender()?;
        // Receive derandomization bit d.
        let d_buf = self.net_recv()?;
        if d_buf.is_empty() {
            eyre::bail!("send_block: empty derandomization msg");
        }
        let d = d_buf[0] & 1 == 1;

        let key_xor_delta = key ^ self.delta;
        let h_0 = hash_to_block(key, self.my_id, ctr);
        let h_1 = hash_to_block(key_xor_delta, self.my_id, ctr);

        let (hc0, hc1) = if d { (h_1, h_0) } else { (h_0, h_1) };
        let c_0 = xor16(m_0, hc0);
        let c_1 = xor16(m_1, hc1);
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&c_0);
        buf[16..].copy_from_slice(&c_1);
        self.net_send(&buf)?;
        Ok(())
    }

    fn recv_block(&mut self, choice: bool) -> Result<BitOtBlock> {
        let (b, m, ctr) = self.pop_receiver()?;
        let d = b ^ choice;
        self.net_send(&[d as u8])?;

        let buf = self.net_recv()?;
        if buf.len() != 32 {
            eyre::bail!("recv_block: expected 32B ciphertext, got {}", buf.len());
        }
        let mut c_0 = [0u8; 16];
        let mut c_1 = [0u8; 16];
        c_0.copy_from_slice(&buf[..16]);
        c_1.copy_from_slice(&buf[16..]);
        let c_c = if choice { c_1 } else { c_0 };

        let h = hash_to_block(m, self.peer_id, ctr);
        Ok(xor16(c_c, h))
    }

    fn reveal_bit(&mut self, bit: bool) -> Result<()> {
        self.net_send(&[bit as u8])?;
        Ok(())
    }

    fn recv_revealed_bit(&mut self) -> Result<bool> {
        let buf = self.net_recv()?;
        if buf.is_empty() {
            eyre::bail!("recv_revealed_bit: empty msg");
        }
        Ok(buf[0] & 1 == 1)
    }

    fn reveal_block(&mut self, block: BitOtBlock) -> Result<()> {
        self.net_send(&block)?;
        Ok(())
    }

    fn recv_revealed_block(&mut self) -> Result<BitOtBlock> {
        let buf = self.net_recv()?;
        if buf.len() != 16 {
            eyre::bail!("recv_revealed_block: expected 16B, got {}", buf.len());
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&buf);
        Ok(out)
    }
}
