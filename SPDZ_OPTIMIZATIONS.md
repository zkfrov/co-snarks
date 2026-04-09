# SPDZ Performance Optimizations Tracker

**Circuit:** Recursion (UltraHonk recursive verifier, ~730K total gates)  
**Baseline:** 243s total (2.7s PK gen + 242.7s proving) with full MAC, LocalNetwork

## Profiling Breakdown (baseline with MACs)

| Phase | Time | % |
|-------|------|---|
| PK generation | 2.7s | 1% |
| **Oink (commitments)** | **51.4s** | **21%** |
| - wire_commitments (MSM) | 12.6s | 5% |
| - sorted_list_accum | 5.6s | 2% |
| - log_deriv_inverse | 3.2s | 1% |
| - grand_product | 30.0s | 12% |
| **Decider** | **191.3s** | **79%** |
| - sumcheck | 166.2s | 68% |
| - pcs/shplemini | 25.0s | 10% |

---

## Optimizations Applied

### 1. ✅ MAC-Free Mode
**Impact:** ~30-40% speedup estimated (waiting on benchmark)  
**Files:** `spdz/core/src/arithmetic.rs`, `spdz/core/src/types.rs`, `spdz/core/src/preprocessing.rs`, `spdz/core/src/lib.rs`, `spdz/ultrahonk/src/driver.rs`, `spdz/noir/src/lib.rs`

Skip MAC computation entirely during proving. The SNARK proof provides soundness — if a party cheats, the proof won't verify. MAC verification is redundant for collaborative proving.

- `SpdzState::new_mac_free()`: sets mac_key_share=0, mac_free=true
- `mul_many_mac_free()`: Beaver multiplication on share-only (no MAC arithmetic)
- `msm_public_points`: skip MAC MSM (the heaviest single operation)
- `fft`/`ifft`: skip MAC FFT
- `eval_poly`: share-only Horner evaluation
- `add_public`: skip mac_key_share * public multiplication
- `promote_from_trivial`: skip MAC computation
- `scalar_mul_public_point`: skip MAC point multiplication
- `reshare`: skip MAC reconstruction
- `create_lazy_preprocessing_mac_free()`: zero MAC key in preprocessing generation
- `prove_spdz_mac_free()`: top-level API for MAC-free proving

### 2. ✅ Public Sort Optimization
**Impact:** PK gen 40s → 2.7s  
**File:** `spdz/acvm/src/solver.rs`

Range list sorting in `process_range_lists` was using O(n²) MPC oblivious sort for public values. Now uses local sort when all inputs are public.

### 3. ✅ NAF Fix
**Impact:** Correctness fix (was producing wrong circuit)  
**File:** `spdz/acvm/src/solver.rs`

SPDZ solver had a custom NAF implementation that computed actual NAF decomposition instead of bit extraction matching the plain solver.

### 4. ✅ Lazy Preprocessing
**Impact:** No "ran out" errors, minimal RAM  
**File:** Test uses `create_lazy_preprocessing()` instead of pre-allocated batches.

### 5. ✅ Batched open_point_many
**Impact:** N network rounds → 1 for point opens  
**File:** `spdz/core/src/arithmetic.rs`, `spdz/ultrahonk/src/driver.rs`

---

## Optimizations TODO

### 6. Grand Product Batching
**Estimated impact:** ~20s savings (30s → ~10s)  
**File:** `co-noir/co-ultrahonk/src/co_oink/co_oink_prover.rs`

`execute_grand_product_computation_round` calls `batched_grand_product_num_denom` 4 times sequentially, each with its own Beaver `mul_many` = 4 network rounds. These are independent and could be batched into 1 round.

### 7. Open Point+Field in Single Round
**Estimated impact:** ~3-5s savings  
**File:** `spdz/ultrahonk/src/driver.rs`

`open_point_and_field_many` does 2 separate exchanges (points then fields). Could combine into 1 exchange by serializing both into a single buffer.

### 8. Rayon Parallelism for Local Computation
**Estimated impact:** ~10-20% on CPU-bound phases  
**Files:** Various (sumcheck relations, Beaver local arithmetic, FFT)

The sumcheck relation evaluation, Beaver local arithmetic, and FFT/IFFT are single-threaded per party. Adding rayon parallelism to the local parts would help on multi-core machines.

### 9. Proving Key Caching
**Estimated impact:** 2.7s per run saved  
**Approach:** PK generation is deterministic from the circuit bytecode. Serialize the proving key to disk on first run, reload on subsequent runs. Gitignore the cache file.

### 10. Compile-Time MAC-Free (Feature Flag)
**Estimated impact:** ~5-10% on top of runtime MAC-free  
**Approach:** `#[cfg(feature = "mac-free")]` that removes the `mac` field from `SpdzPrimeFieldShare` entirely. Eliminates all zero-arithmetic overhead in operator impls (Add, Sub, Mul, Neg).

### 11. Structured Trace (Shorter Polynomials)
**Estimated impact:** ~30% reduction in FFT/MSM size  
**Approach:** bb uses polynomials of size 728803 (active trace only) with `start_index=1`. Co-snarks uses full 1048576. Using shorter polynomials reduces FFT from O(1M log 1M) to O(730K log 730K) and MSM by 30%.

### 12. Sumcheck Relation Batching (Architectural)
**Estimated impact:** Reduces network rounds in sumcheck  
**Approach:** The `local_mul_vec` / `reshare` split was designed for Rep3. For SPDZ, `local_mul_vec` does a full Beaver protocol (with network). A deferred multiplication API would allow collecting all multiplications across all relations, then opening all epsilon/delta in a single batch. This requires co-ultrahonk changes.

---

## Performance Targets

| Mode | Current | After MAC-free | After all opts |
|------|---------|---------------|---------------|
| Full MAC (LocalNetwork) | 243s | — | — |
| MAC-free (LocalNetwork) | TBD | ~150-170s? | ~120-140s? |
| MAC-free (LAN, 0.1ms) | — | ~170-200s? | ~140-160s? |
| MAC-free (Internet, 50ms) | — | ~10-20min? | ~5-10min? |

---

## Notes

- The **sumcheck** dominates at 68% of proving time. It does 20 rounds × O(circuit_size) local computation per round. Most of this is CPU-bound (relation evaluation), not network-bound.
- With **LocalNetwork** (in-memory channels), network latency is ~0. Over real networks, the ~60 communication rounds become the bottleneck.
- **Rep3** (3-party honest-majority) takes 223s for the same circuit — comparable to SPDZ's 243s. The MPC overhead is small relative to the raw computation.
- For **dark chess**, a turn-based game with ~5 min per move is feasible with current performance. Further optimization could bring this to ~2-3 min.
