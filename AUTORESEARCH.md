# SP1 CPU Prover Optimization — Autoresearch Plan

## Context

We want to make the SP1 CPU prover faster on end-to-end `prove` latency. Rather than pick a favorite optimization and swing, we run an **autoresearch** loop: build the evaluation infrastructure first, measure a trustworthy baseline, then attack whatever the profile actually says is hot. Every change is a one-variable experiment landed against the leaderboard; we refuse to ship wins that don't reproduce on the ladder.

The codebase already has `sp1-perf` (full latency bench), `sp1-perf-executor` (exec-only), CI `suite.yml` (runs S3 fixtures with `-C opt-level=3 -C target-cpu=native`), and rich `tracing` instrumentation on the hot paths. What it does *not* have: a CPU flamegraph command, a leaderboard, or a regression gate. Phase 0 fills those gaps; everything after is experiments.

**Scope (locked with user):** CPU prover only · workload ladder fib→keccak→big · metric = end-to-end prove latency (wall clock of `prove_duration` from `sp1-perf`). No GPU, no recursion-circuit rewrites, no correctness refactors not required by a measured win.

## Principles

1. **Eval loop before optimizations.** Until a single command reproduces a number we trust, nothing else matters.
2. **One variable per experiment.** A PR = one hypothesis. No drive-by cleanups.
3. **Smallest workload that reproduces the win.** Iterate on fib-17k; promote to keccak only when the profile agrees; promote to big only before merge.
4. **Leaderboard or it didn't happen.** Every run logs to [bench/leaderboard.ndjson](bench/leaderboard.ndjson) — commit sha, workload, prove_ms, profile hash, notes. Wins are *deltas vs. a named baseline on the same machine*, never absolute numbers.
5. **Profile first, hypothesize second, code third.** If the profile doesn't show the hotspot you want to fix, you're wrong about the hotspot. Fix that before writing code.
6. **Ship the harness, not just the wins.** The leaderboard, regression gate, and flamegraph command outlive any single optimization.

---

## Phase 0 — Build the evaluation loop ✅ COMPLETE (2026-04-17)

Deliverables (all live under a new `bench/` directory at repo root):

- [bench/run.sh](bench/run.sh) — one command: `bench/run.sh <fib|keccak|big> [--profile]`.
  - Sets `RUSTFLAGS="-C opt-level=3 -C target-cpu=native"`, pins `RAYON_NUM_THREADS`, warm-boots once, runs N=3 measured iterations, picks median.
  - Pre-builds `sp1-perf` in release mode, then runs the binary directly (no `cargo run` overhead on measured iterations).
  - Parses `prove_duration` from `sp1-perf --json` stdout (extended `PerfSummary` with `Serialize` derive + `--json` CLI flag).
  - `--profile` flag wraps the run in `samply record` and writes `profile.json` next to the result.
- [bench/fixtures/fetch.sh](bench/fixtures/fetch.sh) — fetches ELFs + stdins from S3: `fib` → `v6/fibonacci-20k`, `keccak` → `v6/keccak256-100kb`, `big` → `v6/ssz-withdrawals`.
- [bench/leaderboard.ndjson](bench/leaderboard.ndjson) — append-only. Each line: `{sha, branch, workload, threads, prove_ms_median, prove_ms_stddev, host, notes, iterations, all_prove_ms}`.
- [bench/compare.py](bench/compare.py) — reads leaderboard, prints delta table with Wilcoxon rank-sum p-values.
- [bench/README.md](bench/README.md) — three commands: `run`, `profile`, `compare`.

Exit criteria met: back-to-back fib runs yielded 35,380ms vs 35,753ms = **1.05% variance** (< 2% threshold). Harness is trustworthy.

## Phase 1 — Baseline & hotspot survey ✅ COMPLETE (2026-04-20)

Baselines recorded on `succinct-gpu-02` (64 threads), sha `40a3d6193`:

| Workload | prove_ms_median | stddev |
|----------|-----------------|--------|
| fib      | 35,380          | 138    |
| keccak   | 42,847          | 483    |
| big      | 47,697          | 559    |

Hotspot table: [bench/hotspots.md](bench/hotspots.md). Key findings:

1. **~30% of self-time is rayon/crossbeam work-stealing overhead** — `crossbeam_epoch::with_handle` (17%), `try_advance` (7%), `Stealer::steal` (5%), `Mutex::lock_contended` (1.5%). This is consistent across all workloads.
2. **~24% is `BinomialExtensionField::mul`** (KoalaBear degree-4 extension multiplication, many monomorphizations). Core sumcheck/fold arithmetic.
3. **~8.5% is Poseidon2 hashing** — already AVX-512 optimized (`PackedKoalaBearAVX512` confirmed in profile).

SIMD sanity check: **AVX-512 is active.** Profile shows `p3_koala_bear::x86_64_avx512::poseidon2` symbols. Runtime detection via `target-cpu=native` works; no additional feature flags needed. **E7 eliminated.**

## Phase 2 — Hypothesis queue (re-ranked after Phase 1 profile)

The queue is a living [bench/experiments.md](bench/experiments.md). **Re-ranked based on Phase 1 profile evidence.** Each entry states a **hypothesis**, an **expected delta** (back-of-envelope), a **measurement protocol** (which workload, which metric), and a **kill condition** (what would make us abandon).

Prioritized order (by profile evidence):

- **E1. Rayon thread tuning.** 🔴 TOP PRIORITY — 30% of self-time is crossbeam/rayon overhead. Vary `RAYON_NUM_THREADS` across {physical/2=16, physical=32, logical=64}. Hypothesis: 64 threads causes massive work-stealing contention on this SMT host. Zero-code, runs first.
  - Kill: <1% delta at any thread count.
- **E2. Allocator swap.** `mimalloc` or `jemalloc` under `sp1-perf`. Hypothesis: Mutex::lock_contended (1.5%) may be allocator-related. One-line Cargo change.
  - Kill: <1% delta.
- **E3. Parallelize Merkle commit over columns.** [slop/crates/merkle-tree/src/p3.rs](slop/crates/merkle-tree/src/p3.rs) — Poseidon2 is 8.5% but may be serialized per column. Check if `par_iter` over columns exists; add if not.
  - Kill: Poseidon2 is already parallel, or <1% delta.
- **E4. Basefold fold-loop batching.** [slop/crates/basefold/](slop/crates/basefold/) — if folds are per-round sequential kernels, batch consecutive rounds to keep data hot in L2.
  - Kill: Folds already batched, or <1% delta.
- **E5. Trace-gen shard concurrency.** [crates/hypercube/src/prover/shard.rs](crates/hypercube/src/prover/shard.rs) — check whether per-shard trace gen serializes on a lock or a single rayon pool; fix if so.
  - Kill: Already concurrent, or <1% delta.
- **E6. PGO / BOLT.** Build `sp1-perf` with `-C profile-generate`, run fib, rebuild with `profile-use`. Pure build change, free if it helps.
  - Kill: <2% delta (not worth the build complexity).
- ~~**E7. Field arithmetic SIMD feature gates.**~~ **ELIMINATED** — Phase 1 confirmed AVX-512 is already active.

Anti-patterns (will reject even if they profile well): any change that adds a new abstraction layer, changes public APIs without an end-to-end win >5%, or is not reproducible on a second machine.

## Phase 3 — Experiment loop (IN PROGRESS)

### Completed experiments

**E1. Rayon thread tuning → -19.8% on big** ✅ SHIPPED
- Code change: `slop/crates/futures/src/rayon.rs` defaults to `num_cpus::get_physical()`, called from `cpu_worker_builder()`
- Root cause: SMT siblings caused 30% overhead in crossbeam work-stealing; at 32 threads overhead drops to 12%

**E2. mimalloc allocator → -7.2% fib, -0.9% big** ✅ CONFIRMED
- Code change: optional `mimalloc` feature in sp1-perf with `#[global_allocator]`
- Decision needed: ship as sp1-sdk feature, document as recommendation, or sp1-perf only

**E6. PGO → -11.5% fib, -10.1% big** ✅ CONFIRMED
- Build-only change, no code. ~10x build overhead for training run.
- Suitable for release builds / CI prover image, not developer iteration.

### Cumulative results (E1+E2+E6 vs original baseline)

| Workload | Original | Optimized | Total Delta |
|----------|---------|-----------|-------------|
| fib      | 35,380ms | 23,465ms | **-33.7%** |
| keccak   | 42,847ms | 31,569ms | **-26.3%** |
| big      | 47,697ms | 34,081ms | **-28.5%** |

### Eliminated experiments
- E3. Merkle commit parallelism — **ELIMINATED**: p3_merkle_tree already uses `par_chunks_exact_mut`
- E4. Basefold fold-loop batching — **DEPRIORITIZED**: folds already use `par_iter`; inter-round batching blocked by data deps
- E5. Trace-gen shard concurrency — **ELIMINATED**: trace gen <0.1% of prove time in all profiled workloads
- E7. SIMD feature gates — **ELIMINATED**: AVX-512 already active

### Ready to ship
- **E1 (physical cores)**: Code change in `slop-futures` + `sp1-prover`. -19.8% on big. No user-facing API changes.
- **E2 (mimalloc)**: Optional feature in sp1-perf. -7.2% fib / -0.9% big. Needs decision on scope.
- **E6 (PGO)**: Build-time optimization. -10.1% big. Suitable for release/CI builds only.

### Protocol (unchanged)
1. Branch from latest `main`. One experiment = one branch.
2. Implement minimal change.
3. Run `bench/run.sh fib` (N=3). If <1% improvement or noisy, kill.
4. Run `bench/run.sh keccak` (N=3). If regresses, kill.
5. Profile-diff: before/after, confirm the hot function shrank.
6. Run `bench/run.sh big` (N=3) on the final candidate. Log to leaderboard.
7. Open PR with leaderboard diff. fmt + clippy must pass.

One experiment per PR. Don't stack.

## Phase 4 — Consolidation & regression gate

After ~3-5 wins land:

1. Re-record a `baseline-<date+n>` on current main.
2. Add a CI job (extend [.github/workflows/suite.yml](.github/workflows/suite.yml)) that runs `bench/run.sh fib` on every PR touching `crates/prover/`, `crates/hypercube/`, or `slop/`, fails on >5% regression vs. the most recent baseline tag, comments the delta on the PR.
3. The big fixture stays manual-trigger (too slow for every PR).

## Critical files to modify / reuse

- Reuse: [crates/perf/src/perf.rs](crates/perf/src/perf.rs), [crates/perf/run_s3.sh](crates/perf/run_s3.sh), [.github/workflows/suite.yml](.github/workflows/suite.yml).
- Extend: `PerfSummary` in [crates/perf/src/perf.rs:39-48](crates/perf/src/perf.rs#L39-L48) — add a `--json` output mode, additive only, don't break existing stdout users.
- Create: everything under `bench/` described above. No new code in `crates/` or `slop/` during Phases 0-1.
- Likely targets in Phases 2-3 (confirm first): [slop/crates/multilinear/](slop/crates/multilinear/), [slop/crates/sumcheck/](slop/crates/sumcheck/), [slop/crates/merkle-tree/src/p3.rs](slop/crates/merkle-tree/src/p3.rs), [slop/crates/basefold/](slop/crates/basefold/), [crates/hypercube/src/prover/shard.rs](crates/hypercube/src/prover/shard.rs).

## Verification

End-to-end, the plan is working iff:

- `bench/run.sh fib` on a cold clone reproduces a `prove_ms_median` within 2% of what the committer reported.
- `bench/compare.py baseline-<date> HEAD` produces a clean delta table.
- A deliberately-introduced slowdown (e.g., `sleep(10ms)` in a hot function) is caught by the CI regression gate.
- `cargo test --release -p sp1-prover test_e2e_node` still passes on the final merged state — perf wins that break correctness don't count.

## Not in scope

GPU/CUDA paths, recursion-circuit rewrites, algorithmic changes to the PCS (switching basefold→whir, radix-2→radix-4 FFT rewrites), new feature flags visible to SDK users, and anything touching the guest zkVM.
