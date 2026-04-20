# Hotspot Table — baseline-2026-04-20

Host: succinct-gpu-02 (64 threads), sha `40a3d6193`, branch `tamir/autoresearch-cpu`

## fib (median 35,380ms)

| Rank | Self% | Function | Source | What it does |
|------|-------|----------|--------|-------------|
| 1 | 17.4% | `crossbeam_epoch::default::with_handle` | crossbeam-epoch (dep) | Rayon epoch-based GC — thread-local handle acquisition for work-stealing deque |
| 2 | 7.8% | `BinomialExtensionField::mul` (monomorphization 1) | p3-field | Extension field multiplication (KoalaBear degree-4 extension) |
| 3 | 7.6% | `crossbeam_epoch::internal::Global::try_advance` | crossbeam-epoch (dep) | Epoch advancement / GC sweeps during rayon work-stealing |
| 4 | 5.3% | `crossbeam_deque::Stealer::steal` | crossbeam-deque (dep) | Rayon work-stealing deque steal operation |
| 5 | 5.2% | `DiffusionMatrixKoalaBear::permute_mut` (AVX-512) | p3-koala-bear | Poseidon2 internal diffusion permutation — AVX-512 PackedKoalaBear |
| 6 | 6.1% | kernel `0xffffffff85cc0b6{0,5}` | kernel | Likely futex/scheduler syscalls from lock contention |
| 7 | 2.7% | `BinomialExtensionField::mul` (mono 2) | p3-field | Same as #2, different call site monomorphization |
| 8 | 2.4% | `BinomialExtensionField::mul` (mono 3) | p3-field | Same as #2 |
| 9 | 2.3% | `Permutation::permute` | p3-symmetric | Poseidon2 outer permutation dispatch |
| 10 | 1.7% | `BinomialExtensionField::mul` (mono 4) | p3-field | Same as #2 |

**Total BinomialExtensionField::mul (all monomorphizations): ~24%**
**Total crossbeam/rayon overhead: ~30%**
**Total Poseidon2 (diffusion + permute): ~8.5%**
**Mutex lock contention: ~1.5%**

## keccak (median 42,847ms)

Nearly identical profile to fib — same top-5 in same order:
- crossbeam_epoch::with_handle: 14.8%
- BinomialExtensionField::mul (all): ~26%
- crossbeam_epoch::try_advance: 6.2%
- Poseidon2 DiffusionMatrixKoalaBear: 5.1%
- crossbeam_deque::steal: 4.6%

## big (median 47,697ms)

Same pattern:
- crossbeam_epoch::with_handle: 17.5%
- BinomialExtensionField::mul (all): ~21%
- crossbeam_epoch::try_advance: 7.2%
- crossbeam_deque::steal: 5.4%
- Poseidon2 DiffusionMatrixKoalaBear: 4.3%

## Top-3 Optimization Candidates

### 1. Rayon/crossbeam contention (~30% of prove time)
`crossbeam_epoch::with_handle` + `try_advance` + `Stealer::steal` + `Mutex::lock_contended`
combined are **~30%** of self-time across all workloads. This is rayon work-stealing overhead,
likely from either:
- Too many threads (64 logical on this machine, possibly SMT)
- Very fine-grained rayon parallelism creating excessive task churn
- crossbeam epoch GC thrashing under high thread counts

**Action:** E1 (rayon tuning) is now the highest-priority experiment. Also investigate
whether reducing rayon task granularity (larger chunks in `par_iter` / `par_chunks`) can
reduce steal/epoch overhead.

### 2. Extension field multiplication (~24% of prove time)
`BinomialExtensionField<KoalaBear, 4>::mul` across many monomorphizations. This is the core
sumcheck/fold arithmetic — the field operations that dominate sumcheck evaluation.

**Action:** These are in p3 upstream code. Check if there's a SIMD-vectorized extension field
multiply path (like the Poseidon2 AVX-512 path). If not, this could be a candidate for an
optimized kernel, but it's upstream p3 code so harder to change.

### 3. Poseidon2 hashing (~8.5% of prove time)
`DiffusionMatrixKoalaBear::permute_mut` (already using AVX-512) + `Permutation::permute`.
This is Merkle tree hashing in the PCS commitment phase.

**Action:** Already AVX-512 optimized. Improvement would come from reducing the number of
hashes (commitment structure changes) rather than making individual hashes faster. Lower
priority than #1 and #2.

## SIMD Status

- **AVX-512 is ACTIVE** for Poseidon2 (`PackedKoalaBearAVX512` in profile)
- Feature flags: `p3-maybe-rayon` has `parallel` feature enabled
- No additional `nightly-features` or explicit AVX-512 feature flags needed — p3 0.3.2-succinct
  uses runtime detection via `target-cpu=native` RUSTFLAG
- **E7 (SIMD feature gates) is eliminated** — SIMD is already on
