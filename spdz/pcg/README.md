# spdz-pcg

**SPDZ preprocessing backed by oblivious 2-party PCG over BN254 Fr.**

The "glue" crate that wires:

- **[`pcg-bn254`](https://github.com/zkfrov/pcg-bn254)** — sub-linear Ring-LPN
  PCG primitives (DPF, DMPF, OLE → Beaver triple conversion).
- **[`mpz`](https://github.com/privacy-scaling-explorations/mpz)** — garbled
  circuits, Ferret silent OT, KOS extension, Chou-Orlandi base OT.
- **`spdz-core`** — SPDZ-style preprocessing trait + Beaver triple
  consumption.

…into one preprocessing source that produces SPDZ Beaver triples
**without any party learning the cross-term positions** — the oblivious
2-party DPF generation contribution.

## What's here

### Public API

| Item | Purpose |
|---|---|
| `Prg2pcSession<N>` | 2PC PRG via garbled circuits. The atomic primitive that the the oblivious gen builds on. Backends: `new` (ideal_cot, fast/insecure), `new_ferret` (Ferret + ideal_rcot bootstrap), **`new_ferret_co`** (Chou-Orlandi → KOS → Ferret, production). |
| `dpf_gen_oblivious` | Oblivious 2-party DPF gen. No α leak. Output matches `pcg_core::dpf::gen_dpf` byte-for-byte (so `eval_all` works unchanged). |
| `dpf_gen_oblivious_mult_beta` / `_additive_alpha` | PCG-flavored wrappers (multiplicative β / additive α). |
| `dmpf_gen_oblivious` | t² DPF loop on a shared `Prg2pcSession`. |
| `gen_seed_2party_oblivious` | Full Ring-LPN PCG seed: 4 cross-term DMPFs. |
| `Seed2PartyOblivious::expand_to_ole` | Local expansion → length-N OLE correlations. |
| `PcgPreprocessing::new_ring_lpn_oblivious_batched` | The top-level: SPDZ preprocessing source backed by oblivious PCG. Pre-generates `n_batches` independent batches sharing one Ferret bootstrap. |
| `MuxNetwork<N>` | Application-level network multiplexer — wraps any `Network` and exposes N independent logical networks for parallel cross-term generation over a single underlying socket. |
| `FerretBitOt<N>` | Production `BitOt` backed by Ferret silent OT (used by the leaf correction and α/β conversions inside `dpf_gen_oblivious`). |

### Test layout

Tests live in `tests/`. Notable ones:

- `pcg_oblivious_e2e.rs` — full Ring-LPN PCG over oblivious gen, validates OLE invariant.
- `spdz_oblivious_pcg_e2e.rs` — top-level `PcgPreprocessing` produces valid Beaver triples.
- `dpf_oblivious_chou_orlandi.rs` — production OT stack (Chou-Orlandi → KOS → Ferret).
- `parallel_dmpf_demo.rs` / `parallel_dmpf_muxed.rs` — 4-cross-term parallelism (one socket each).
- `prg_2pc_bench.rs` / `dpf_bench.rs` — micro-benchmarks.

### Performance (release mode, single 8-core machine)

- First `Prg2pcSession::expand` call: ~113 ms (Ferret LPN bootstrap)
- Subsequent expands: **~1.8 ms each** (62× speedup)
- Per oblivious DPF at log_n=20: **~85 ms**
- Full Ring-LPN PCG batch at t=64 (16K DPFs), 8 cores: **~3 min**
- Chess-style preprocessing (t=32): **<1 min per game session**

See `tests/dpf_bench.rs` and `pcg-bn254/docs/OBLIVIOUS_DPF_GEN_DESIGN.md` for
detailed numbers and methodology.

## Provenance & references

Oblivious 2-party DPF generation is the main contribution
of this crate. It composes existing protocols rather than introducing new
cryptography. All credit for the underlying constructions belongs to the
original authors.

### Cryptographic foundations

**DPF / FSS / 2-party gen**:
- Boyle, Gilboa, Ishai. *Function Secret Sharing.* Eurocrypt 2015,
  [ePrint 2018/707](https://eprint.iacr.org/2018/707).
- Boyle, Gilboa, Ishai. *Function Secret Sharing: Improvements and
  Extensions.* CCS 2016.
- Doerner, shelat. *Scaling ORAM for Secure Computation.* CCS 2017,
  [ePrint 2017/827](https://eprint.iacr.org/2017/827) — §3 (PPRF) and §4
  (2-party DPF gen with secret α).
- Boyle, Gilboa, Ishai. *Secure Computation with Preprocessing via Function
  Secret Sharing.* TCC 2019.

**Ring-LPN PCG**:
- Boyle, Couteau, Gilboa, Ishai, Kohl, Scholl. *Efficient Pseudorandom
  Correlation Generators from Ring-LPN.* CRYPTO 2020,
  [ePrint 2020/1417](https://eprint.iacr.org/2020/1417). Direct construction.
- Bombar, Bui, Couteau, Ducros, Hazay, Meyer. *FOLEAGE: F4OLE-Based
  Multi-Party Computation for Boolean Circuits.* 2024. Closest analog;
  inspired our overall architecture.

**SPDZ**:
- Damgård, Pastro, Smart, Zakarias. *Multiparty Computation from Somewhat
  Homomorphic Encryption.* CRYPTO 2012,
  [ePrint 2011/535](https://eprint.iacr.org/2011/535).
- Damgård, Keller, Larraia, Pastro, Scholl, Smart. *Practical Covertly
  Secure MPC for Dishonest Majority — or: Breaking the SPDZ Limits.*
  ESORICS 2013 ("MASCOT" preprocessing).

**Garbled circuits**:
- Yao. *How to generate and exchange secrets.* FOCS 1986. Original GC.
- Kolesnikov, Schneider. *Improved Garbled Circuit: Free XOR Gates and
  Applications.* ICALP 2008. Free-XOR.
- Bellare, Hoang, Keelveedhi, Rogaway. *Efficient Garbling from a Fixed-Key
  Blockcipher.* IEEE S&P 2013. AES-NI fixed-key garbling.
- Zahur, Rosulek, Evans. *Two Halves Make a Whole: Reducing Data Transfer
  in Garbled Circuits using Half Gates.* Eurocrypt 2015,
  [ePrint 2014/756](https://eprint.iacr.org/2014/756). Half-gates.
- Guo, Katz, Wang, Yu. *Better Concrete Security for Half-Gates Garbling
  (in the Multi-Instance Setting).* CRYPTO 2020,
  [ePrint 2019/074](https://eprint.iacr.org/2019/074). Correlation-robust
  hash.

**OT extension**:
- Chou, Orlandi. *The Simplest Protocol for Oblivious Transfer.*
  Latincrypt 2015, [ePrint 2015/267](https://eprint.iacr.org/2015/267).
  CO15 base OT.
- Keller, Orsini, Scholl. *Actively Secure OT Extension with Optimal
  Overhead.* CRYPTO 2015,
  [ePrint 2015/546](https://eprint.iacr.org/2015/546). KOS15.
- Yang, Wang, Zhao. *Ferret: Fast Extension for Correlated OT with Small
  Communication.* CCS 2020,
  [ePrint 2020/924](https://eprint.iacr.org/2020/924). Silent OT via LPN.
- Gilboa. *Two Party RSA Key Generation.* CRYPTO 1999. Bit-by-bit OLE
  conversion (`mul_to_add_share`).

### Implementations re-used

- **[`mpz`](https://github.com/privacy-scaling-explorations/mpz)** by Privacy
  & Scaling Explorations — the entire OT and GC stack (Ferret, KOS, Chou-
  Orlandi, mpz-garble's `Garbler`/`Evaluator`, mpz-circuits' built-in
  AES-128 boolean circuit). Oblivious DPF gen would have been a multi-month effort
  without mpz — the design doc originally estimated 3-4 weeks for a from-
  scratch GMW evaluator + AES circuit before realizing mpz already had it
  all. Massive thanks to the mpz team.
- **[`cryprot-core`](https://crates.io/crates/cryprot-core)** — fixed-key
  AES correlation-robust hash, used for the DPF tree PRG (matches Guo et
  al. 2019).
- **[`co-snarks`](https://github.com/TaceoLabs/co-snarks)** by TACEO Labs —
  the SPDZ framework this crate plugs into. `frov-co-snarks` is a fork.
- **[`pcg-bn254`](https://github.com/zkfrov/pcg-bn254)** — sister crate with
  the standalone PCG primitives.
- **[`arkworks`](https://github.com/arkworks-rs)** — field arithmetic.

### What we did differently

The design choices here aren't novel cryptography — they're engineering
trade-offs for the specific use case (BN254 SNARKs + chess-style 2-party
prep). Worth calling out:

1. **BN254 Fr**, not GF(2^k) or smaller fields. SNARK-relevant; most
   academic PCG work targets binary/small fields.

2. **Bit-linear leaf F-map** in `pcg-core::dpf::seed_to_field`
   (`F::from_le_bytes_mod_order(seed)` instead of SHA3). Enables the
   secure leaf correction to use 128 Gilboa bit-OTs instead of a 2PC
   SHA3 circuit (~24K AND gates). Statistical bias 2^-126 (128-bit seed
   into 254-bit field) — negligible.

3. **Two PRG-2PC calls per level on per-party sub-tree state.** Naive
   "joint-seed PRG" produces correction words incompatible with the
   trusted-dealer DPF; we keep per-party sub-tree state shared via
   XOR-shares and run the PRG twice per level. Resulting CWs match
   `pcg_core::dpf::gen_dpf` byte-for-byte → `eval_all` works unchanged.

4. **Public reveal of `D = f_0 − f_1 − β` at the leaf.** Equivalent (up
   to a ±1 sign) to the public `final_correction`; reveals nothing
   beyond what's in the key. Lets us compute the sign correction with a
   single bit-OT.

5. **Persistent `Garbler`/`Evaluator` across `expand` calls** in
   `Prg2pcSession`. mpz-garble doesn't enforce single-use Garblers, so
   we hold the state and amortize the Ferret LPN bootstrap (~113 ms)
   across all DPFs in a session — bringing per-expand cost to ~1.8 ms.
   Big single-line win for production performance.

6. **`MuxNetwork<N>`** — generic application-level network multiplexer
   that works over any `Network` trait (LocalNetwork in tests, TCP/TLS
   for production, etc.). For native QUIC, `mpc_net::quic::QuicNetwork`
   already has `fork()` (uses native bidirectional QUIC streams) which
   is more efficient — the multiplexer is a transport-agnostic fallback.

7. **Multi-batch oblivious PCG via pre-generation** in
   `PcgPreprocessing::new_ring_lpn_oblivious_batched`. One Ferret
   bootstrap amortized across N PCG batches (each with fresh sparse
   polys derived from `private_seed`).

### Oblivious DPF gen doc

The full design rationale, performance analysis, and engineering history
of the oblivious 2-party DPF generation lives in
[`pcg-bn254/docs/OBLIVIOUS_DPF_GEN_DESIGN.md`](../../../pcg-bn254/docs/OBLIVIOUS_DPF_GEN_DESIGN.md).

## License

Same as `co-snarks` (MIT-or-Apache-2.0).
