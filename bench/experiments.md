# Experiment Log

## E1. Rayon thread tuning

**Status:** ✅ COMPLETE — SHIPPED
**Hypothesis:** 64 threads (logical cores) causes massive crossbeam work-stealing contention. Reducing to physical cores (32) or half (16) should reduce the ~30% overhead.
**Expected delta:** 5-15% improvement on fib
**Actual delta:** -19.3% fib, -16.8% keccak, -19.8% big

### Thread sweep results (fib, succinct-gpu-02)

| Threads | prove_ms | vs 64t |
|---------|---------|--------|
| 16      | 31,214  | -11.8% |
| 24      | 28,674  | -19.0% |
| **32**  | **28,026** | **-20.8%** |
| 48      | 31,508  | -10.9% |
| 64      | 35,380  | baseline |

### Profile diff (fib, 64t → 32t)
- crossbeam_epoch::with_handle: 17.4% → 7.9% (down 55%)
- crossbeam_epoch::try_advance: 7.6% → 1.5% (down 80%)
- crossbeam_deque::steal: 5.3% → 2.9% (down 45%)
- Total crossbeam overhead: ~30% → ~12%

### Code change
- `slop/crates/futures/src/rayon.rs`: `init_global_pool()` defaults to `num_cpus::get_physical()` when `RAYON_NUM_THREADS` is not set
- `crates/prover/src/worker/builder.rs`: calls `init_global_pool()` at start of `cpu_worker_builder()`

## E2. Allocator swap (mimalloc)

**Status:** ✅ CONFIRMED WIN — needs decision on shipping mechanism
**Hypothesis:** `Mutex::lock_contended` (1.5%) may be glibc malloc lock contention. mimalloc has per-thread arenas.
**Expected delta:** 1-5%
**Actual delta:** -7.2% fib, -2.3% keccak, -0.9% big (on top of E1)

### Results (all at 32 threads / physical cores)

| Workload | glibc | mimalloc | Delta |
|----------|-------|----------|-------|
| fib      | 28,551ms | 26,504ms | -7.2% |
| keccak   | 35,648ms | 34,845ms | -2.3% |
| big      | 38,228ms | 37,899ms | -0.9% |

### Notes
- Win is strongest on fib (highest allocation rate per compute), weakest on big
- Allocator must be set by the final binary (cannot be set in a library crate)
- Options: (a) add `mimalloc` feature to sp1-sdk, (b) document it as a user recommendation, (c) add it to sp1-perf only
- Code: `sp1-perf` Cargo.toml has `mimalloc` optional dep + `#[global_allocator]` behind `#[cfg(feature = "mimalloc")]`

## E3. Parallelize Merkle commit over columns

**Status:** ❌ ELIMINATED — already parallel
**Hypothesis:** Poseidon2 hashing (8.5%) may be serialized per column in Merkle tree construction.
**Finding:** p3_merkle_tree's `first_digest_layer()` and `compress_and_inject()` already use `par_chunks_exact_mut` via `p3_maybe_rayon`. The slop wrapper calls these functions which handle parallelism internally. Profile shows no Merkle-specific functions as hotspots — only the underlying Poseidon2 permutation, which is the inherent cost.

## E4. Basefold fold-loop batching

**Status:** ❌ DEPRIORITIZED
**Finding:** Fold operations are already parallelized via rayon par_iter in fold_mle(). Inter-round batching is not feasible because each round depends on the previous round's output. The conversion overhead between base/extension fields between rounds could be optimized, but requires more invasive changes and the fold operations don't dominate the profile after E1 tuning.

## E5. Trace-gen shard concurrency

**Status:** ❌ ELIMINATED — not in profile
**Finding:** Trace generation doesn't appear in the fib/keccak/big profiles at all (<0.1% of prove time). The prover's time is dominated by sumcheck/PCS arithmetic and hashing, not trace generation.

## E6. PGO (Profile-Guided Optimization)

**Status:** ✅ CONFIRMED WIN — build-only change
**Hypothesis:** PGO lets LLVM optimize hot paths (branch prediction, inlining, code layout) based on actual runtime profile
**Expected delta:** 2-5%
**Actual delta:** -11.5% fib, -9.4% keccak, -10.1% big (on top of E1+E2)

### Results (PGO + mimalloc + physical cores vs mimalloc + physical cores)

| Workload | No PGO | PGO | Delta |
|----------|--------|-----|-------|
| fib      | 26,504ms | 23,465ms | -11.5% |
| keccak   | 34,845ms | 31,569ms | -9.4% |
| big      | 37,899ms | 34,081ms | -10.1% |

### Cumulative results (E1+E2+E6 vs original baseline)

| Workload | Original (64t, glibc) | Optimized (32t, mimalloc, PGO) | Total Delta |
|----------|----------------------|-------------------------------|-------------|
| fib      | 35,380ms             | 23,465ms                      | -33.7% |
| keccak   | 42,847ms             | 31,569ms                      | -26.3% |
| big      | 47,697ms             | 34,081ms                      | -28.5% |

### Build procedure
1. `RUSTFLAGS="-C opt-level=3 -C target-cpu=native -Cprofile-generate=/tmp/pgo-data" cargo build --release -p sp1-perf`
2. Run fib workload once (slow, ~10x overhead)
3. `$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata merge -o merged.profdata /tmp/pgo-data/*.profraw`
4. `RUSTFLAGS="-C opt-level=3 -C target-cpu=native -Cprofile-use=merged.profdata" cargo build --release -p sp1-perf`

### Notes
- PGO requires system llvm-profdata matching Rust's LLVM version (LLVM 21 for current Rust nightly)
- Instrumented build has ~10x overhead — only run the smallest workload (fib) for training
- PGO is a build-time optimization: it changes how LLVM compiles the code, not what code runs
- Could be integrated into CI for release builds or the prover docker image

## E8. Remove par_bridge from hot paths

**Status:** ✅ COMPLETE — PR #2729
**Hypothesis:** `par_bridge()` uses a mutex internally for work distribution, causing `Mutex::lock_contended` (1.3% in profile). Replacing with `par_chunks_mut` / `into_par_iter` removes the mutex.
**Expected delta:** 1-3%
**Actual delta:** -6.8% fib, -7.6% keccak, -7.1% big (on top of E1+E2)

### Changed files
- `slop/crates/multilinear/src/restrict.rs` — `mle_fix_last_variable`: `.chunks().zip().par_bridge()` → `.par_chunks_mut().enumerate()`
- `slop/crates/jagged/src/poly.rs` — `eval`: `.iter().zip().enumerate().par_bridge()` → `(0..N).into_par_iter()`
- `slop/crates/jagged/src/poly.rs` — `partial_jagged_little_polynomial_evaluation`: `.chunks_mut().enumerate().par_bridge()` → `.par_chunks_mut().enumerate()`
- `crates/hypercube/src/prover/zerocheck/sum_as_poly.rs` — `.chunks().zip().enumerate().par_bridge()` → `(0..N).into_par_iter()` with manual indexing

## ~~E7. SIMD feature gates~~

**Status:** ELIMINATED — AVX-512 confirmed active in Phase 1 profile
