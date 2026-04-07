# Upgrade Path: co-snarks bb 3.0.0 → bb 4.2.0

## Verified Baseline
- co-snarks (original, commit before 5d950c4a) + bb 3.0.0-nightly.20251104 + Noir beta.17
- **VKs are byte-identical** between co-snarks and bb 3.0.0
- **bb 3.0.0 verifies co-snarks proofs** successfully
- Circuit builder is correct and produces identical circuits

## Changes Needed (bb 3.0.0 → 4.2.0)

### 1. Transcript Protocol Changes

#### 1a. Eta: 3 independent → 1 with powers ✅ (already done)
- **bb 3.0.0**: `get_challenges(["eta", "eta_two", "eta_three"])` → 3 independent values
- **bb 4.2.0**: `get_challenge("eta")` → eta, eta², eta³
- **Files**: oink_prover.rs, oink_verifier.rs, co_oink_prover.rs, oink_recursive_verifier.rs

#### 1b. Challenge split: 128/126 → 127/127 ✅ (already done)
- **bb 3.0.0**: LO=128 bits, HI=126 bits
- **bb 4.2.0**: LO=127 bits, HI=127 bits
- **File**: keccak_hash.rs

#### 1c. Split-before-reduce ✅ (already done)
- **bb 3.0.0**: reduce to Fr THEN split
- **bb 4.2.0**: split raw hash THEN reduce each half
- **File**: transcript.rs

#### 1d. VK hash computation (maybe changed)
- **bb 3.0.0**: `hash_through_transcript(domain_separator, transcript)`
- **bb 4.2.0**: `hash_with_origin_tagging(transcript)` — uses Codec serialization
- **Impact**: May change VK hash for the same VK. Need to verify.
- **File**: verification_key.rs in co-snarks

### 2. Pairing Point Accumulator ✅ (already done)
- **bb 3.0.0**: 16 limbs (4 BigField × 4 limbs), non-zero default values
- **bb 4.2.0**: 8 packed values (4 BigField → 2 lo/hi each), zeros for default
- **Files**: ultra_builder.rs, constants.rs

### 3. Noir Version
- **bb 3.0.0**: Noir beta.17
- **bb 4.2.0**: Noir beta.19 (Aztec ships post-beta.19 nargo)
- **Impact**: ACIR format changes (msgpack v2/v3, MemoryAddress u32, no ExpressionWidth)
- **Files**: Cargo.toml, co-brillig/*, co-acvm/*

### 4. Circuit Builder Changes
- Mostly refactoring (VKs identical between versions for same circuit)
- `populate_public_inputs_block` extracted as separate method
- `create_add_gate` now delegates to `create_big_add_gate`
- `create_big_mul_gate` removed
- No functional impact on circuit output

### 5. Sumcheck/Prover Changes
- 531 lines changed in sumcheck.hpp — need to audit
- 96 lines changed in ultra_prover.cpp
- May include virtual round handling, ZK changes, or padding changes

## Testing Strategy
1. Apply changes incrementally
2. After each change, verify co-snarks self-verification passes
3. After all changes, verify bb 4.2.0 can verify co-snarks proofs
4. Test with both Keccak and Poseidon2 transcripts
