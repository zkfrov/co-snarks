# Upgrade Status: co-snarks → bb 4.2.0 / Aztec Compatibility

## Proven Facts
1. **co-snarks (original) + bb 3.0.0 = WORKS** — VKs identical, bb verifies co-snarks proofs
2. **Noir beta.19 compiles** — just need `cargo update -p keccak@0.2.0 --precise 0.2.0-rc.0`
3. **Transcript fixes work** — eta powers, 127-bit split, split-before-reduce
4. **Accumulator fix works** — 8 zero values matching bb 4.2.0
5. **Proof format matches** — 199 fields, same VK header (log_size, num_pub, offset)

## Current Blocker
VK commitments differ between co-snarks and bb 4.2.0 (only 13/59 match).
Headers match but precomputed polynomial commitments differ.
This means the circuit builder produces different gates.

## What's Done
- [x] Noir beta.19 bump + keccak pin
- [x] co-brillig: MemoryAddress usize → u32
- [x] co-acvm: Remove ExpressionWidth, update BrilligCall predicate
- [x] Eta: 3 independent → 1 with powers
- [x] Challenge split: 128/126 → 127/127
- [x] Split-before-reduce in transcript
- [x] Accumulator: 8 zeros instead of 16 non-zero limbs
- [x] PAIRING_POINT_ACCUMULATOR_SIZE: 16 → 8

## What Remains
- [ ] Port circuit builder changes from bb 3.0.0 → 4.2.0
  - 443 insertions, 489 deletions in ultra_circuit_builder.cpp
  - Key changes to audit:
    - `create_add_gate` → delegates to `create_big_add_gate`
    - `create_big_mul_gate` removed
    - `create_ecc_add_gate` changes
    - `create_gates_from_plookup_accumulators` changes
    - Range constraint changes
    - Non-native field changes
- [ ] Port VK hash computation change (hash_with_origin_tagging)
- [ ] Port transcript changes (202 lines in transcript.hpp)
- [ ] Port sumcheck changes (531 lines in sumcheck.hpp)
- [ ] Regenerate all test vectors with beta.19 nargo
- [ ] End-to-end verification: co-snarks proof verified by bb 4.2.0

## Files Changed So Far
- Cargo.toml (beta.19)
- Cargo.lock (regenerated + keccak pin)
- co-noir/co-brillig/src/memory.rs
- co-noir/co-brillig/src/brillig_vm.rs
- co-noir/co-acvm/src/solver.rs
- co-noir/co-acvm/src/solver/brillig_call_solver.rs
- co-noir/co-builder/src/ultra_builder.rs
- co-noir/co-builder/src/keys/proving_key.rs (has debug prints - remove before commit)
- co-noir/co-noir-common/src/constants.rs
- co-noir/co-noir-common/src/transcript.rs
- co-noir/co-noir-common/src/keccak_hash.rs (committed in 5d950c4a)
- co-noir/ultrahonk/src/oink/oink_prover.rs
- co-noir/ultrahonk/src/oink/oink_verifier.rs
- co-noir/co-ultrahonk/src/co_oink/co_oink_prover.rs
- co-noir/co-builder/src/honk_verifier/oink_recursive_verifier.rs
- test_vectors/noir/add3u64/kat/* (beta.19 circuit)
- test_vectors/noir/poseidon/kat/* (beta.19 circuit)
- scripts/bump_noir_beta19.sh
- scripts/UPGRADE_PATH.md
- scripts/UPGRADE_STATUS.md
