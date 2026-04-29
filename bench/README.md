# SP1 CPU Prover Benchmarks

## Setup

Fetch fixtures from S3 (requires AWS CLI):

```sh
bench/fixtures/fetch.sh
```

## Run a benchmark

```sh
bench/run.sh <fib|keccak|big> [--profile] [--iterations N] [--threads N] [--notes TEXT]
```

This builds `sp1-perf` in release mode, runs N=3 measured iterations (after a warm-up),
picks the median `prove_duration`, and appends a result to `bench/leaderboard.ndjson`.

Examples:

```sh
# Quick iteration on the smallest workload
bench/run.sh fib

# Profile with samply (writes profile-<workload>-<sha>.json)
bench/run.sh fib --profile

# Full ladder before merging
bench/run.sh fib && bench/run.sh keccak && bench/run.sh big
```

## Compare two runs

```sh
bench/compare.py <baseline_sha> <candidate_sha>
```

Prints a delta table for every workload that has entries for both SHAs:

```
Workload         Baseline (ms)  Candidate (ms)      Delta    p-value
-------------------------------------------------------------------
fib                      1234.0          1180.0      -4.4%     0.0495
keccak                   5678.0          5500.0      -3.1%     0.0832
```

## Leaderboard

Results are stored in `bench/leaderboard.ndjson` (append-only). Each line:

```json
{"sha":"abc1234","branch":"main","workload":"fib","threads":16,"prove_ms_median":1234.0,"prove_ms_stddev":12.3,"host":"bench-machine","notes":"baseline-2025-04-17","iterations":3,"all_prove_ms":[1230.0,1234.0,1238.0]}
```
