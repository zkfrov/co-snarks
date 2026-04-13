//! Ferret-based Beaver Triple Generation for SPDZ
//!
//! Uses mpz's Ferret silent-OT to generate bulk RCOTs efficiently,
//! then converts to Beaver triples via Gilboa's technique:
//!
//!   RCOT (mpz): Sender holds K, Δ. Receiver holds choice b, gets M = K ⊕ b·Δ.
//!
//!   Gilboa (per bit j, for mul x * y with sender=x, receiver=y):
//!     - Sender hashes K_j → k0_j ∈ F, and K_j ⊕ Δ → k1_j ∈ F
//!     - Sender sends τ_j = x · 2^j − (k1_j − k0_j)
//!     - Receiver hashes M_j → m_j = k_{y_j}_j ∈ F
//!     - Receiver computes: s_R_j = m_j + y_j · τ_j = k0_j + y_j · x · 2^j
//!     - Sender output: s_S_j = −k0_j
//!     - Sum: Σ s_S_j + Σ s_R_j = y · x  ✓
//!
//! For an additive Beaver triple a · b = c with a = a₀+a₁, b = b₀+b₁:
//!   c = a₀b₀ + a₀b₁ + a₁b₀ + a₁b₁
//!   (a₀b₀, a₁b₁) are local. Two Gilboa rounds compute shares of the cross
//!   terms a₀b₁ (P0 sender, P1 receiver) and a₁b₀ (P1 sender, P0 receiver).
//!
//! Each party therefore needs BOTH an RCOT Sender and an RCOT Receiver.
//!
//! Bootstrap: uses `ideal_rcot` from mpz for the base COT. For production this
//! should be replaced with KOS or Chou-Orlandi base OT. Since the SNARK
//! proof provides soundness (mac-free mode), the ideal bootstrap is
//! acceptable for the chess demo but documented as such.

use ark_ff::{BigInteger, PrimeField};
use futures::executor::block_on;
use mpc_net::Network;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot::{
    ferret::{Receiver as FerretReceiver, Sender as FerretSender},
    ideal::rcot::{ideal_rcot, IdealRCOTReceiver, IdealRCOTSender},
};
use mpz_ot_core::{
    ferret::FerretConfig,
    rcot::{RCOTReceiver, RCOTSender},
};
use rand::{RngCore, SeedableRng};
use std::sync::Arc;

use super::async_io::SyncToAsyncIo;
use crate::types::SpdzPrimeFieldShare;

/// Chunk size in VALUES for Gilboa. With 254-bit BN254 Fr and 32-byte
/// serialized field elements, each chunk sends ~4096*254*32 = 33MB of τ,
/// well under the 256MB WS max frame.
const GILBOA_CHUNK: usize = 4096;

/// Ferret sender built on ideal-RCOT bootstrap.
type Sender = FerretSender<IdealRCOTSender>;
/// Ferret receiver built on ideal-RCOT bootstrap.
type Receiver = FerretReceiver<IdealRCOTReceiver>;

/// Ferret preprocessing session: each party holds a Sender (for when it's
/// the "x-party" in Gilboa) and a Receiver (for when it's the "y-party").
pub struct FerretSession<N: Network> {
    party_id: usize,
    sender: Sender,
    receiver: Receiver,
    ctx: Context,
    // Channel used for exchanging Gilboa adjustment messages τ (field elements).
    // We reuse the same async context's IO.
    _net: Arc<N>,
}

impl<N: Network + Unpin + 'static> FerretSession<N> {
    /// Create a Ferret session. Both parties call this; it performs the
    /// initial Flush that exchanges seeds.
    pub fn new(net: Arc<N>) -> eyre::Result<Self> {
        let party_id = net.id();
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

        // Bootstrap RCOT using ideal_rcot (placeholder; see module docs).
        // Both parties derive their bootstrap from a shared seed via the
        // network — here we pick locally but in the ideal functionality
        // the seed is exchanged during flush.
        let seed = {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            Block::from(b)
        };
        let delta = {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            Block::from(b)
        };

        let (bootstrap_sender, _unused_recv) = ideal_rcot(seed, delta);
        let (_unused_send, bootstrap_receiver) = ideal_rcot(seed, delta);

        let config = FerretConfig::default();
        let sender_seed = {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            Block::from(b)
        };
        let receiver_seed = {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            Block::from(b)
        };

        let sender = FerretSender::new(config.clone(), sender_seed, bootstrap_sender);
        let receiver = FerretReceiver::new(config, receiver_seed, bootstrap_receiver);

        // Wrap sync Network in async I/O for mpz Context.
        let io = SyncToAsyncIo::new(net.clone());
        let ctx = Context::new_single_threaded(io);

        Ok(Self {
            party_id,
            sender,
            receiver,
            ctx,
            _net: net,
        })
    }

    /// Alloc+flush the RCOT sender for `count` RCOTs. Does the LPN/I/O work
    /// upfront. Subsequent `consume_sender(n)` calls are in-memory only.
    pub fn prepare_sender(&mut self, count: usize) -> eyre::Result<Block> {
        RCOTSender::alloc(&mut self.sender, count)
            .map_err(|e| eyre::eyre!("alloc sender: {e}"))?;
        block_on(self.sender.flush(&mut self.ctx))
            .map_err(|e| eyre::eyre!("flush sender: {e}"))?;
        Ok(self.sender.delta())
    }

    /// Consume `n` previously-prepared RCOT sender outputs (no I/O).
    pub fn consume_sender(&mut self, n: usize) -> eyre::Result<Vec<Block>> {
        let out = self
            .sender
            .try_send_rcot(n)
            .map_err(|e| eyre::eyre!("try_send_rcot: {e}"))?;
        Ok(out.keys)
    }

    /// Alloc+flush the RCOT receiver for `count` RCOTs.
    pub fn prepare_receiver(&mut self, count: usize) -> eyre::Result<()> {
        RCOTReceiver::alloc(&mut self.receiver, count)
            .map_err(|e| eyre::eyre!("alloc receiver: {e}"))?;
        block_on(self.receiver.flush(&mut self.ctx))
            .map_err(|e| eyre::eyre!("flush receiver: {e}"))?;
        Ok(())
    }

    /// Consume `n` previously-prepared RCOT receiver outputs (no I/O).
    pub fn consume_receiver(&mut self, n: usize) -> eyre::Result<(Vec<bool>, Vec<Block>)> {
        let out = self
            .receiver
            .try_recv_rcot(n)
            .map_err(|e| eyre::eyre!("try_recv_rcot: {e}"))?;
        Ok((out.choices, out.msgs))
    }

    pub fn party_id(&self) -> usize {
        self.party_id
    }
}

/// Hash a 128-bit RCOT output block into a field element (uniformly).
/// Uses SHA3-256 with a per-call domain tag to prevent correlations.
fn block_to_field<F: PrimeField>(block: Block, tag: u64) -> F {
    use sha3::{Digest, Sha3_256};
    let bytes: [u8; 16] = block.into();
    let mut hasher = Sha3_256::new();
    hasher.update(b"FERRET-GILBOA-RO\x00");
    hasher.update(tag.to_le_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    F::from_le_bytes_mod_order(&digest)
}

/// Gilboa multiplication: Sender holds `x_values`, Receiver holds `y_values`.
/// Returns additive shares of `x_i * y_i` for each i.
///
/// Uses `n * field_bits` RCOTs. `tau` is exchanged over `net` as a flat
/// `Vec<F>` of length `n * field_bits`.
///
/// `net` is the sync network for sending τ (auxiliary msg, not part of mpz).
fn gilboa_send<F: PrimeField, N: Network + Unpin + 'static>(
    session: &mut FerretSession<N>,
    net: &N,
    x_values: &[F],
) -> eyre::Result<Vec<F>> {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let total = x_values.len() * field_bits;
    if total == 0 {
        return Ok(Vec::new());
    }
    // One flush for all chunks.
    let delta = session.prepare_sender(total)?;
    let mut out = Vec::with_capacity(x_values.len());
    for chunk in x_values.chunks(GILBOA_CHUNK) {
        out.extend(gilboa_send_chunk(session, net, chunk, delta)?);
    }
    Ok(out)
}

fn gilboa_send_chunk<F: PrimeField, N: Network + Unpin + 'static>(
    session: &mut FerretSession<N>,
    net: &N,
    x_values: &[F],
    delta: Block,
) -> eyre::Result<Vec<F>> {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let n = x_values.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let total = n * field_bits;

    // Step 1: Consume `total` pre-prepared RCOT sender outputs (no I/O).
    let keys = session.consume_sender(total)?;
    debug_assert_eq!(keys.len(), total);

    // Step 2: Receive derandomization bits d_i from receiver so we can
    // align the RCOT choices to the receiver's actual y-bits.
    let other = 1 - session.party_id();
    let d_bytes = net.recv(other).map_err(|e| eyre::eyre!("recv d: {e}"))?;

    // Compute k0, k1, τ, sender-share.
    //   With d known: key_0 = K ⊕ d·Δ, key_1 = K ⊕ (1−d)·Δ.
    //   k0 = H(key_0), k1 = H(key_1), τ = x*2^j − (k1 − k0), share -= k0.
    let mut taus: Vec<F> = Vec::with_capacity(total);
    let mut sender_shares: Vec<F> = Vec::with_capacity(n);

    for k in 0..n {
        let x = x_values[k];
        let mut pow = F::one();
        let mut share = F::zero();
        for j in 0..field_bits {
            let idx = k * field_bits + j;
            let d_bit = (d_bytes[idx / 8] >> (idx & 7)) & 1 == 1;
            let key = keys[idx];
            let key_xor_delta = key ^ delta;
            let (key_0, key_1) = if d_bit {
                (key_xor_delta, key)
            } else {
                (key, key_xor_delta)
            };
            let k0 = block_to_field::<F>(key_0, idx as u64);
            let k1 = block_to_field::<F>(key_1, idx as u64);
            taus.push(x * pow - (k1 - k0));
            share -= k0;
            pow.double_in_place();
        }
        sender_shares.push(share);
    }

    // Step 3: Send τ vector to the other party. Serialize as compressed bytes.
    let mut buf = Vec::with_capacity(total * 32);
    for t in &taus {
        ark_serialize::CanonicalSerialize::serialize_compressed(t, &mut buf)
            .map_err(|e| eyre::eyre!("serialize tau: {e}"))?;
    }
    net.send(other, &buf).map_err(|e| eyre::eyre!("send tau: {e}"))?;

    Ok(sender_shares)
}

fn gilboa_recv<F: PrimeField, N: Network + Unpin + 'static>(
    session: &mut FerretSession<N>,
    net: &N,
    y_values: &[F],
) -> eyre::Result<Vec<F>> {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let total = y_values.len() * field_bits;
    if total == 0 {
        return Ok(Vec::new());
    }
    session.prepare_receiver(total)?;
    let mut out = Vec::with_capacity(y_values.len());
    for chunk in y_values.chunks(GILBOA_CHUNK) {
        out.extend(gilboa_recv_chunk(session, net, chunk)?);
    }
    Ok(out)
}

fn gilboa_recv_chunk<F: PrimeField, N: Network + Unpin + 'static>(
    session: &mut FerretSession<N>,
    net: &N,
    y_values: &[F],
) -> eyre::Result<Vec<F>> {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let n = y_values.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let total = n * field_bits;

    // Step 1: Get RCOT receiver output with CHOSEN choices = bits of y_values.
    //
    // CRITICAL: mpz's RCOT gives RANDOM choices — we need to pick choice bits.
    // The standard conversion is: choose choices r_i at random, reveal
    //   d_i = r_i XOR y_i
    // to the sender, and the sender "adjusts" the keys. mpz's higher-level
    // OT (COT) does this internally. To simplify, we derandomize manually:
    //
    //   After RCOT: receiver has (r_i, M_i = K_i XOR r_i * Δ).
    //   Desired choice is b_i. Set d_i = r_i XOR b_i and send d_i to sender.
    //   Sender, based on d_i, shifts keys so that effective K'_i, K'_i XOR Δ
    //   correspond to receiver choice b_i. Since we send τ AFTER, we can
    //   absorb the d_i into the τ computation directly.
    //
    // For this scaffold, we rely on the caller to implement the derandomization
    // in gilboa_send (which knows d_i via the net.recv). See TODO below.

    let (random_choices, msgs) = session.consume_receiver(total)?;

    // Compute d_i = random_choice_i XOR desired_bit_i, send to sender.
    let mut d_bits: Vec<u8> = Vec::with_capacity((total + 7) / 8);
    let mut byte = 0u8;
    for k in 0..n {
        let y_big = y_values[k].into_bigint();
        for j in 0..field_bits {
            let idx = k * field_bits + j;
            let r = random_choices[idx];
            let b = y_big.get_bit(j);
            let d = r ^ b;
            if d {
                byte |= 1 << (idx & 7);
            }
            if (idx & 7) == 7 {
                d_bits.push(byte);
                byte = 0;
            }
        }
    }
    if total & 7 != 0 {
        d_bits.push(byte);
    }
    let other = 1 - session.party_id();
    net.send(other, &d_bits).map_err(|e| eyre::eyre!("send d: {e}"))?;

    // Receive τ vector from sender.
    let tau_bytes = net.recv(other).map_err(|e| eyre::eyre!("recv tau: {e}"))?;
    let mut cursor = &tau_bytes[..];
    let mut taus: Vec<F> = Vec::with_capacity(total);
    for _ in 0..total {
        let t: F = ark_serialize::CanonicalDeserialize::deserialize_compressed(&mut cursor)
            .map_err(|e| eyre::eyre!("deserialize tau: {e}"))?;
        taus.push(t);
    }

    // Compute receiver shares.
    //   hashed = H(M_i) (same hash as sender's k_{b_i})
    //   share_k = sum_j hashed_{k,j} + b_{k,j} * τ_{k,j}
    let mut recv_shares: Vec<F> = Vec::with_capacity(n);
    for k in 0..n {
        let y_big = y_values[k].into_bigint();
        let mut share = F::zero();
        for j in 0..field_bits {
            let idx = k * field_bits + j;
            let m = msgs[idx];
            let hashed = block_to_field::<F>(m, idx as u64);
            let b = y_big.get_bit(j);
            share += hashed;
            if b {
                share += taus[idx];
            }
        }
        recv_shares.push(share);
    }

    Ok(recv_shares)
}

/// Generate `count` Beaver triples using Ferret OT.
///
/// Both parties run this in parallel. Returns (triples, mac_key_share) where
/// `triples[i] = (a_i, b_i, c_i)` with c = a * b and MAC=0 (mac-free mode).
pub fn generate_triples_via_ferret<F: PrimeField, N: Network + Unpin + 'static>(
    count: usize,
    net: Arc<N>,
) -> eyre::Result<(
    Vec<(
        SpdzPrimeFieldShare<F>,
        SpdzPrimeFieldShare<F>,
        SpdzPrimeFieldShare<F>,
    )>,
    F,
)> {
    let party_id = net.id();
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    let a_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();
    let b_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();
    let mac_key_share = F::rand(&mut rng);

    let mut session = FerretSession::new(net.clone())?;

    // Round 1: Party 0 is sender (x = a_0), Party 1 is receiver (y = b_1).
    //          Outputs: shares of a_0 * b_1.
    let cross1 = if party_id == 0 {
        gilboa_send(&mut session, &net, &a_shares)?
    } else {
        gilboa_recv(&mut session, &net, &b_shares)?
    };

    // Round 2: Party 1 is sender (x = a_1), Party 0 is receiver (y = b_0).
    //          Outputs: shares of a_1 * b_0.
    let cross2 = if party_id == 0 {
        gilboa_recv(&mut session, &net, &b_shares)?
    } else {
        gilboa_send(&mut session, &net, &a_shares)?
    };

    let c_shares: Vec<F> = (0..count)
        .map(|i| a_shares[i] * b_shares[i] + cross1[i] + cross2[i])
        .collect();

    let triples = (0..count)
        .map(|i| {
            (
                SpdzPrimeFieldShare::new(a_shares[i], F::zero()),
                SpdzPrimeFieldShare::new(b_shares[i], F::zero()),
                SpdzPrimeFieldShare::new(c_shares[i], F::zero()),
            )
        })
        .collect();

    Ok((triples, mac_key_share))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use crate::types::combine_field_element;
    use mpc_net::local::LocalNetwork;

    #[test]
    fn test_ferret_triple_generation() {
        let mut nets = LocalNetwork::new(2).into_iter();
        let net0 = Arc::new(nets.next().unwrap());
        let net1 = Arc::new(nets.next().unwrap());

        let count = 4;

        let h0 = std::thread::spawn(move || {
            generate_triples_via_ferret::<Fr, _>(count, net0).unwrap()
        });
        let h1 = std::thread::spawn(move || {
            generate_triples_via_ferret::<Fr, _>(count, net1).unwrap()
        });

        let (triples0, _mk0) = h0.join().unwrap();
        let (triples1, _mk1) = h1.join().unwrap();

        for i in 0..count {
            let (a0, b0, c0) = &triples0[i];
            let (a1, b1, c1) = &triples1[i];

            let a = combine_field_element(*a0, *a1);
            let b = combine_field_element(*b0, *b1);
            let c = combine_field_element(*c0, *c1);

            assert_eq!(a * b, c, "Triple {i}: a*b must equal c");
        }
    }
}
