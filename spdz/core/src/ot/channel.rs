//! Network-to-Channel adapter with proper buffering.
//!
//! The OT library (ocelot/scuttlebutt) uses stream-oriented I/O:
//! many small read_bytes/write_bytes calls. Our Network trait is
//! message-oriented: each send/recv is a discrete message.
//!
//! This adapter buffers writes until flush(), and buffers reads
//! to handle messages larger than the requested read size.

use mpc_net::Network;

pub struct NetworkChannel<'a, N: Network> {
    net: &'a N,
    other_id: usize,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<'a, N: Network> NetworkChannel<'a, N> {
    pub fn new(net: &'a N) -> Self {
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

impl<'a, N: Network> scuttlebutt::AbstractChannel for NetworkChannel<'a, N> {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        let mut written = 0;

        // Drain existing buffer first
        if self.read_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_pos;
            let to_copy = available.min(bytes.len());
            bytes[..to_copy].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
            written += to_copy;

            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
        }

        // Keep receiving until we have enough bytes
        while written < bytes.len() {
            let data = self.net.recv(self.other_id)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let needed = bytes.len() - written;
            let to_copy = data.len().min(needed);
            bytes[written..written + to_copy].copy_from_slice(&data[..to_copy]);
            written += to_copy;

            // Buffer leftover
            if to_copy < data.len() {
                self.read_buf = data;
                self.read_pos = to_copy;
            }
        }

        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.write_buf.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.write_buf.is_empty() {
            let data = std::mem::take(&mut self.write_buf);
            self.net.send(self.other_id, &data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
        Ok(())
    }
}
