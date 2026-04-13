//! AsyncRead+AsyncWrite wrapper around our sync `mpc_net::Network`.
//!
//! mpz uses async I/O (futures::AsyncRead + AsyncWrite) and its Context requires
//! `'static + Send + Sync`. We bridge by blocking inside poll_read/poll_write —
//! works because we drive the futures with `futures::executor::block_on` on a
//! single thread.
//!
//! Used only when feature = "ferret" is enabled.

use futures::{AsyncRead, AsyncWrite};
use mpc_net::Network;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Owned async-IO wrapper around an `Arc<N>`-shared sync network.
///
/// Satisfies `'static + Send + Sync + Unpin` required by `mpz_common::Context`.
pub struct SyncToAsyncIo<N: Network> {
    net: Arc<N>,
    other_id: usize,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<N: Network> SyncToAsyncIo<N> {
    pub fn new(net: Arc<N>) -> Self {
        let other_id = 1 - net.id();
        Self {
            net,
            other_id,
            write_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<N: Network + Unpin> AsyncRead for SyncToAsyncIo<N> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // Serve from buffer if available
        if self.read_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_pos;
            let to_copy = available.min(buf.len());
            let start = self.read_pos;
            buf[..to_copy].copy_from_slice(&self.read_buf[start..start + to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(to_copy));
        }

        // Buffer empty — block on recv
        let other = self.other_id;
        let data = self
            .net
            .recv(other)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);

        // Buffer the rest if any
        if to_copy < data.len() {
            self.read_buf = data;
            self.read_pos = to_copy;
        }

        Poll::Ready(Ok(to_copy))
    }
}

impl<N: Network + Unpin> AsyncWrite for SyncToAsyncIo<N> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let data = std::mem::take(&mut self.write_buf);
        let other = self.other_id;
        self.net
            .send(other, &data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}
