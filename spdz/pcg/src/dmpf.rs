//! Distributed Multi-Point Function (DMPF) over BN254 Fr.
//!
//! A DMPF encodes a t-sparse function f: [N] → F where f(α_i) = β_i for
//! t distinct points, and f(x) = 0 elsewhere.
//!
//! Construction: **Batch Code**. Based on the `BatchCodeDmpf` in the `dmpf`
//! Rust crate (MatanHamilis/dmpf, IEEE S&P 2025).
//!
//! Key insight: the "3 hash functions" aren't independent random hashes —
//! they're derived from a random **permutation** of [3N] such that each
//! target slot is mapped to by exactly ONE (source_position, hash_fn) pair.
//! This guarantees that at any zero position x, the 3 candidate buckets
//! give 3 indices that are DIFFERENT from the placement indices of all
//! non-zero points. So the DPF lookups all return 0 → sum is 0.
//!
//! Outline:
//! 1. Generate a random permutation π : [3N] → [N] (each value in [N] appears
//!    3 times in the output). Interpret as: slot i stores source position π(i).
//! 2. For source position x ∈ [N], its 3 candidate target slots are the 3 `i`
//!    values such that π(i) = x. Slot i decomposes to (bucket, idx) =
//!    (i / bucket_size, i % bucket_size).
//! 3. Place each of t non-zero points in ONE of its 3 candidate buckets
//!    (random-walk with eviction, cuckoo-style).
//! 4. Each of B buckets gets a single-point DPF: the point's β at its
//!    placed index, or zero-DPF for empty buckets.
//! 5. Evaluation at x: look up x's 3 (bucket, idx) pairs from the
//!    permutation, sum the bucket DPF evals.

use crate::dpf::{eval_all as dpf_eval_all, gen_dpf, DpfKey};
use ark_ff::PrimeField;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const HASH_FUNCTIONS: usize = 3;

#[derive(Clone, Debug)]
pub struct DmpfKey<F: PrimeField> {
    pub log_n: u32,
    pub num_buckets: usize,
    pub bucket_log_size: u32,
    /// Seed for the permutation (shared by both parties).
    pub perm_seed: [u8; 32],
    /// One DPF key per bucket.
    pub bucket_dpfs: Vec<DpfKey<F>>,
    pub party: u8,
}

pub struct DmpfParams {
    pub log_n: u32,
    pub num_buckets: usize,
    pub bucket_size: usize,
    pub bucket_log_size: u32,
}

impl DmpfParams {
    pub fn new(log_n: u32, t: usize) -> Self {
        // ~1.5·t buckets for larger t, 2t for very small t.
        let overhead_pct = if t < 30 { 100 } else { 50 };
        let num_buckets = ((t * (100 + overhead_pct)) / 100).max(1);
        let n = 1usize << log_n;
        // bucket_size = ceil(N·H / B). Round up to power of 2 so the DPF
        // domain is exact. This may over-allocate some slots but keeps the
        // DPF depth standard.
        let raw_bucket_size = (n * HASH_FUNCTIONS).div_ceil(num_buckets);
        let bucket_log_size = usize::ilog2(raw_bucket_size.next_power_of_two()) as u32;
        let bucket_size = 1usize << bucket_log_size;
        Self {
            log_n,
            num_buckets,
            bucket_size,
            bucket_log_size,
        }
    }
}

/// Generate the permutation table: `mapping[source][i] = target_slot` for
/// i in 0..3, where `target_slot ∈ [num_buckets * bucket_size)`.
///
/// Built from a Fisher-Yates shuffle of the slot list [0, 3N) where each slot
/// is pre-assigned to source position (slot_idx % N).
fn build_perm_mapping(
    log_n: u32,
    params: &DmpfParams,
    perm_seed: &[u8; 32],
) -> Vec<[usize; HASH_FUNCTIONS]> {
    let n = 1usize << log_n;
    let mut rng = ChaCha20Rng::from_seed(*perm_seed);

    // permutation[i] = source position. Start with (0..N).cycle().take(3N).
    let mut permutation: Vec<usize> = (0..n).cycle().take(HASH_FUNCTIONS * n).collect();
    // Fisher-Yates shuffle.
    for i in 0..permutation.len() {
        let remaining = permutation.len() - i;
        let swap_idx = i + (rng.r#gen::<usize>() % remaining);
        permutation.swap(i, swap_idx);
    }

    // For each source position, find its 3 target slots. Use an auxiliary
    // table: count per source.
    let mut mapping: Vec<[usize; HASH_FUNCTIONS]> = vec![[usize::MAX; HASH_FUNCTIONS]; n];
    let mut counts: Vec<usize> = vec![0; n];
    for (slot, &source) in permutation.iter().enumerate() {
        let c = counts[source];
        mapping[source][c] = slot;
        counts[source] += 1;
    }
    debug_assert!(counts.iter().all(|&c| c == HASH_FUNCTIONS));
    mapping
}

fn slot_to_bucket_idx(slot: usize, bucket_size: usize) -> (usize, usize) {
    (slot / bucket_size, slot % bucket_size)
}

/// Place each point in one of its 3 candidate buckets (cuckoo-style).
fn place_points(
    points: &[u64],
    params: &DmpfParams,
    mapping: &[[usize; HASH_FUNCTIONS]],
    rng: &mut ChaCha20Rng,
) -> Option<Vec<(usize, usize)>> {
    let t = points.len();
    if t == 0 {
        return Some(Vec::new());
    }

    let candidates: Vec<[(usize, usize); HASH_FUNCTIONS]> = points
        .iter()
        .map(|&x| {
            let slots = &mapping[x as usize];
            let mut c = [(0usize, 0usize); HASH_FUNCTIONS];
            for i in 0..HASH_FUNCTIONS {
                c[i] = slot_to_bucket_idx(slots[i], params.bucket_size);
            }
            c
        })
        .collect();

    let mut point_to_bucket: Vec<Option<(usize, usize)>> = vec![None; t];
    let mut bucket_to_point: Vec<Option<usize>> = vec![None; params.num_buckets];

    let max_iters = t * t * t + 100;
    let mut queue: Vec<usize> = (0..t).collect();
    let mut iters = 0;

    while let Some(cur_point) = queue.pop() {
        iters += 1;
        if iters > max_iters {
            return None;
        }
        let start: usize = rng.r#gen::<usize>() % HASH_FUNCTIONS;
        let mut placed = false;
        for offset in 0..HASH_FUNCTIONS {
            let fn_id = (start + offset) % HASH_FUNCTIONS;
            let (bucket, idx) = candidates[cur_point][fn_id];
            if bucket_to_point[bucket].is_none() {
                bucket_to_point[bucket] = Some(cur_point);
                point_to_bucket[cur_point] = Some((bucket, idx));
                placed = true;
                break;
            }
        }
        if !placed {
            let fn_id: usize = rng.r#gen::<usize>() % HASH_FUNCTIONS;
            let (bucket, idx) = candidates[cur_point][fn_id];
            let evicted = bucket_to_point[bucket].replace(cur_point).unwrap();
            point_to_bucket[cur_point] = Some((bucket, idx));
            point_to_bucket[evicted] = None;
            queue.push(evicted);
        }
    }

    Some(
        point_to_bucket
            .into_iter()
            .map(|opt| opt.expect("all points placed"))
            .collect(),
    )
}

pub fn gen_dmpf<F: PrimeField>(
    log_n: u32,
    points: &[(u64, F)],
    rng_seed: u64,
) -> (DmpfKey<F>, DmpfKey<F>) {
    let t = points.len();
    let params = DmpfParams::new(log_n, t);
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);

    let (perm_seed, placements) = loop {
        let mut perm_seed = [0u8; 32];
        rng.fill(&mut perm_seed);
        let mapping = build_perm_mapping(log_n, &params, &perm_seed);
        let positions: Vec<u64> = points.iter().map(|p| p.0).collect();
        if let Some(p) = place_points(&positions, &params, &mapping, &mut rng) {
            break (perm_seed, p);
        }
    };

    let mut bucket_content: Vec<Option<(usize, usize)>> = vec![None; params.num_buckets];
    for (point_idx, (bucket, idx)) in placements.iter().enumerate() {
        bucket_content[*bucket] = Some((point_idx, *idx));
    }

    let mut k0_dpfs: Vec<DpfKey<F>> = Vec::with_capacity(params.num_buckets);
    let mut k1_dpfs: Vec<DpfKey<F>> = Vec::with_capacity(params.num_buckets);
    for (bucket_idx, content) in bucket_content.iter().enumerate() {
        let (alpha, beta) = match content {
            Some((pi, idx)) => (*idx as u64, points[*pi].1),
            None => (0u64, F::zero()),
        };
        let dpf_seed: u64 = rng.r#gen::<u64>() ^ (bucket_idx as u64);
        let (k0, k1) = gen_dpf::<F>(params.bucket_log_size, alpha, beta, dpf_seed);
        k0_dpfs.push(k0);
        k1_dpfs.push(k1);
    }

    let key_p0 = DmpfKey {
        log_n,
        num_buckets: params.num_buckets,
        bucket_log_size: params.bucket_log_size,
        perm_seed,
        bucket_dpfs: k0_dpfs,
        party: 0,
    };
    let key_p1 = DmpfKey {
        log_n,
        num_buckets: params.num_buckets,
        bucket_log_size: params.bucket_log_size,
        perm_seed,
        bucket_dpfs: k1_dpfs,
        party: 1,
    };
    (key_p0, key_p1)
}

pub fn eval_all<F: PrimeField>(key: &DmpfKey<F>) -> Vec<F> {
    let n = 1usize << key.log_n;
    let bucket_size = 1usize << key.bucket_log_size;
    let params = DmpfParams {
        log_n: key.log_n,
        num_buckets: key.num_buckets,
        bucket_size,
        bucket_log_size: key.bucket_log_size,
    };
    let mapping = build_perm_mapping(key.log_n, &params, &key.perm_seed);

    let bucket_tables: Vec<Vec<F>> = key
        .bucket_dpfs
        .iter()
        .map(|dpf| dpf_eval_all(dpf))
        .collect();

    let mut out = Vec::with_capacity(n);
    for x in 0..n {
        let mut val = F::zero();
        for i in 0..HASH_FUNCTIONS {
            let slot = mapping[x][i];
            let (bucket, idx) = slot_to_bucket_idx(slot, bucket_size);
            val += bucket_tables[bucket][idx];
        }
        out.push(val);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;

    fn combine(v0: &[Fr], v1: &[Fr]) -> Vec<Fr> {
        v0.iter().zip(v1.iter()).map(|(a, b)| *a + *b).collect()
    }

    #[test]
    fn dmpf_small_t4_log8() {
        let log_n = 8u32;
        let points: Vec<(u64, Fr)> = vec![
            (3, Fr::from(10u64)),
            (42, Fr::from(20u64)),
            (100, Fr::from(30u64)),
            (200, Fr::from(40u64)),
        ];
        let (k0, k1) = gen_dmpf::<Fr>(log_n, &points, 42);
        let v0 = eval_all(&k0);
        let v1 = eval_all(&k1);
        let combined = combine(&v0, &v1);

        let mut expected = vec![Fr::from(0u64); 1 << log_n];
        for (a, b) in &points {
            expected[*a as usize] = *b;
        }
        for (i, (exp, got)) in expected.iter().zip(combined.iter()).enumerate() {
            assert_eq!(got, exp, "position {i}");
        }
    }

    #[test]
    fn dmpf_random_t16_log12() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(77);
        use rand::Rng;
        let log_n = 12u32;
        let n = 1u64 << log_n;
        let t = 16;

        let mut positions = std::collections::HashSet::new();
        while positions.len() < t {
            positions.insert(rng.r#gen::<u64>() % n);
        }
        let points: Vec<(u64, Fr)> = positions
            .into_iter()
            .map(|p| (p, Fr::rand(&mut rng)))
            .collect();

        let (k0, k1) = gen_dmpf::<Fr>(log_n, &points, 1234);
        let v0 = eval_all(&k0);
        let v1 = eval_all(&k1);
        let combined = combine(&v0, &v1);

        let mut expected = vec![Fr::from(0u64); 1 << log_n];
        for (a, b) in &points {
            expected[*a as usize] = *b;
        }
        for (i, (exp, got)) in expected.iter().zip(combined.iter()).enumerate() {
            assert_eq!(got, exp, "position {i}");
        }
    }

    #[test]
    fn dmpf_params_sizes() {
        for (log_n, t) in [(10, 16), (12, 64), (14, 128), (16, 256)] {
            let p = DmpfParams::new(log_n, t);
            eprintln!(
                "log_n={log_n} t={t} → {} buckets × 2^{} per-bucket DPF",
                p.num_buckets, p.bucket_log_size
            );
        }
    }
}
