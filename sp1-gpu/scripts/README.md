# `sp1-gpu/scripts/` — bench comparison driver

This folder holds a small driver that compares the sp1-gpu Criterion
microbenchmarks between **what's currently in your working tree** and
**any other git ref** (a branch, a tag, or a commit SHA), and prints a
side-by-side table with statistical confidence intervals.

If you've never run a Criterion bench before, this README is meant to
be enough on its own — every command below can be copy-pasted.

| File | Purpose |
| --- | --- |
| [`bench-compare.sh`](bench-compare.sh) | The driver you actually run. |
| [`_bench_compare_format.py`](_bench_compare_format.py) | Internal helper that formats the comparison table. You don't call this directly. |

---

## What you get

After the script finishes, you'll see a table that looks roughly like:

```
group                                       current        main           delta      95% CI                t
------------------------------------------  -------------  -------------  ---------  --------------------  -----
commit_multilinears/random/core_2^25        412.3±2.1ms    421.7±1.8ms    -2.23%     [-2.95, -1.51]%       -6.1
jagged_sumcheck/random/core_2^25            188.4±0.9ms    187.1±1.1ms    +0.69%     [-0.07, +1.46]%       +1.8
zerocheck/random/core_2^25                  1.207±0.012s   1.218±0.010s   -0.90%     [-2.21, +0.41]%       -1.4
```

How to read it:

- **`current`** is your working tree (committed *and* uncommitted edits).
- **`<ref>`** (e.g. `main`) is the comparison side.
- **`delta`** is `(current - ref) / ref * 100`. A **negative** number
  means current is **faster** than the ref. Positive = slower.
- **`95% CI`** is a confidence interval on that delta. If the interval
  doesn't cross zero, the change is statistically distinguishable from
  noise within this run.
- **`t`** is the t-statistic. As a rough rule of thumb, `|t| > ~2`
  corresponds to `p < 0.05` for moderate sample sizes.

The CI captures **within-run** noise only — it can't detect cross-run
bias from thermal drift or scheduler luck. To guard against that, use
`--repeat N` (see below) and look at how stable the delta is across
rounds.

---

## Prerequisites

You need:

- **`git`** (you almost certainly have this already)
- **`python3`** (no extra Python packages — only the standard library)
- **`jq`** (used to parse `cargo bench --no-run` output)
- A working **CUDA toolchain** for the sp1-gpu build (same as any
  other build in this repo)

That's it. There is **no one-time setup step** — the first invocation
just does whatever building it needs.

---

## Quick start

> All commands below assume you are at the **repo root** — the directory
> that contains the `sp1-gpu/` folder. If you're not sure where that is,
> run:
>
> ```bash
> cd /path/to/your/sp1/clone   # wherever you cloned sp1-wip / sp1
> pwd                          # should print the repo root
> ls sp1-gpu                   # should list crates/, scripts/, etc.
> ```

### Step 1 — sanity check (recommended on your first run)

Compare your current commit against itself, and run only the smallest
bench. Deltas should be near zero. This is how you confirm everything
is wired up before committing to a long run.

```bash
sp1-gpu/scripts/bench-compare.sh HEAD commit
```

What's happening:
- `HEAD` = "compare against the current commit"
- `commit` = "only run the bench named `commit`" (the smallest one)
- Your current side reuses your already-built `target/` cache (fast).
- The other side has to set up a fresh worktree and build it from
  scratch (slow, but only the first time — see
  [Cache management](#cache-management) below).

### Step 2 — your first real comparison

Compare your working tree against `main`, running every bench:

```bash
sp1-gpu/scripts/bench-compare.sh
```

That's the most common form. With no arguments, it picks `main` as the
ref and runs every bench in the suite.

---

## Common usage patterns

### Run only one bench

Much faster while iterating on a change:

```bash
sp1-gpu/scripts/bench-compare.sh zerocheck
sp1-gpu/scripts/bench-compare.sh jagged
sp1-gpu/scripts/bench-compare.sh commit
```

The bench names are the names you'd see in a `cargo bench --bench <name>`
invocation. The full list is:

| Bench | Crate |
| --- | --- |
| `zerocheck` | `sp1-gpu-zerocheck` |
| `prove_trusted_evaluations` | `sp1-gpu-shard-prover` |
| `jagged` | `sp1-gpu-jagged-sumcheck` |
| `hadamard` | `sp1-gpu-jagged-sumcheck` |
| `commit` | `sp1-gpu-commit` |
| `gkr` | `sp1-gpu-logup-gkr` |

### Compare against a different ref

```bash
# Against another branch
sp1-gpu/scripts/bench-compare.sh some-other-branch

# Against a specific commit (full or short SHA both work)
sp1-gpu/scripts/bench-compare.sh 21aa2f468

# Against a tag
sp1-gpu/scripts/bench-compare.sh v1.2.3
```

### Combine: ref + bench

```bash
sp1-gpu/scripts/bench-compare.sh main jagged
sp1-gpu/scripts/bench-compare.sh some-branch commit
sp1-gpu/scripts/bench-compare.sh 21aa2f468 zerocheck
```

The order is `[ref] [bench]`. Either may be omitted.

### Multiple rounds for tighter confidence

Each `--repeat N` round runs both sides one more time, **alternating
which side goes first** so any time-of-day / thermal effects don't
all land on one side. Per-round samples are pooled before the
t-test, so the CI gets tighter as `N` increases.

```bash
# 3 rounds, all benches, vs main
sp1-gpu/scripts/bench-compare.sh --repeat 3

# 3 rounds, just `jagged`, vs main
sp1-gpu/scripts/bench-compare.sh --repeat 3 jagged

# 5 rounds, just `commit`, vs a feature branch
sp1-gpu/scripts/bench-compare.sh --repeat 5 some-branch commit
```

`-r N` is a shorter alias for `--repeat N`.

Each extra round adds one full pass of every selected bench, so think of
this as "I'm willing to wait N× longer to halve the noise."

---

## Choosing the trace input (`--source`)

Four of the five benches (`commit`, `jagged`, `prove_trusted_evaluations`,
`zerocheck`) accept a trace source. By default they all run on a
synthetic random trace at log-area 25 (i.e. `2^25` field elements).

Pass `--source ARG` (or `-s ARG`) to pick a different input. The same
ARG goes to every selected bench in this invocation.

```bash
# Random trace at the default size (2^25) — same as no flag
sp1-gpu/scripts/bench-compare.sh --source random

# Random at a specific size
sp1-gpu/scripts/bench-compare.sh --source random:24

# Sweep multiple random sizes (each becomes a separate row in the table)
sp1-gpu/scripts/bench-compare.sh --source random:22,24,26

# Override the chip cluster the synthetic trace populates. Default is
# `core` (≈ base RISC-V); `all-chips` populates every chip on the
# machine — worst-case stress, not comparable to any real shard.
sp1-gpu/scripts/bench-compare.sh --source random:24,cluster=all-chips

# Real zkVM execution of one of the bundled sample programs
sp1-gpu/scripts/bench-compare.sh --source real/keccak256

# Trace built from a JSON layout file (must end in .json)
sp1-gpu/scripts/bench-compare.sh --source /tmp/layout.json
```

### Available real programs

`fibonacci`, `fibonacci_blake3`, `ed25519`, `keccak256`, `sha2`,
`ssz_withdrawals`, `tendermint`, `groth16`, `groth16_blake3`,
`plonk`, `plonk_blake3`.

To add more, edit `real_programs()` in
`sp1-gpu/crates/jagged_tracegen/src/test_utils.rs`.

### Caveats

- **`hadamard`** accepts the `random` form (including size sweeps) but
  rejects `json` / `real` — its inputs are raw `Felt`/`Ext` buffers,
  not a chip trace. The `cluster=` modifier is parsed for uniformity
  with the other benches but has no effect on hadamard. When
  `--source` is `json` / `real` and hadamard is in the selection
  (e.g. the default "all benches" run), the script silently drops it
  with a one-line note so the rest of the comparison still runs.
  Explicitly asking for `bench-compare.sh hadamard --source real/X`
  errors out instead.
- **Synthetic chip cluster.** `random` defaults to `cluster=core`
  (≈ base RISC-V, no extensions or precompiles), which is the closest
  synthetic analogue to a fibonacci-shaped real shard.
  `cluster=all-chips` populates every chip the machine knows about —
  not comparable to any real shard, useful only as a worst-case
  stress test. For `zerocheck` in particular, the cluster choice
  matters a lot: per-chip work means spreading the same total area
  across more chips shifts the bench from per-row work toward
  per-chip constants and can make timings look slower without doing
  more "real" computation.
- **Random / JSON traces don't satisfy AIR constraints**, so any proof
  built on top of them would not verify. Timing is still meaningful;
  end-to-end validation is not. See each bench folder's README for
  details.

---

## Fully explicit examples

These spell every option out so you can see the full shape:

```bash
# Compare current vs `some-branch`, run only `commit`, 3 alternating
# rounds, with the keccak256 real trace as input.
sp1-gpu/scripts/bench-compare.sh --repeat 3 --source real/keccak256 \
    some-branch commit

# Same flags, against an explicit SHA, just the `jagged` bench.
sp1-gpu/scripts/bench-compare.sh --repeat 5 --source random \
    21aa2f468 jagged

# Random trace at a specific log-area, all benches.
sp1-gpu/scripts/bench-compare.sh --repeat 1 --source random:24 \
    main

# Sweep three random sizes on `commit`.
sp1-gpu/scripts/bench-compare.sh --repeat 1 --source random:22,24,26 \
    main commit

# `zerocheck` vs `main`, 1 round (the default), with the sha2 real trace.
sp1-gpu/scripts/bench-compare.sh --repeat 1 --source real/sha2 \
    main zerocheck

# JSON-layout source spelled out explicitly.
sp1-gpu/scripts/bench-compare.sh --repeat 1 --source /tmp/layout.json \
    main jagged
```

The argument order is always `[flags...] [ref] [bench_name]`.

---

## Cache management

The first time you compare against a ref, the script creates a git
worktree under `sp1-gpu/.bench-worktrees/<ref>/` and **keeps it** so
re-runs against the same ref are fast (no cold rebuild). These can
take tens of GB of disk.

```bash
# Remove every cached worktree
sp1-gpu/scripts/bench-compare.sh clear

# Remove just one (use the same ref name you compared against)
sp1-gpu/scripts/bench-compare.sh clear main
sp1-gpu/scripts/bench-compare.sh clear some-branch
```

The script will also leave `target/criterion/<bench>/current-r*/`
directories in your main checkout — these are tiny and harmless.
Remove them with `rm -rf target/criterion` whenever you want.

---

## Reducing measurement noise (optional, recommended for small effects)

GPU and memory clocks drift with temperature and power state, which
shows up as run-to-run variation that can mask small (1–3%)
regressions. Locking clocks before benching typically drops noise from
~5% to **<1%**, which is the difference between needing 1 round and
needing 5+.

This needs `sudo`. **You can skip this whole section if you don't have
sudo** — the script still works; you'll just need more `--repeat` rounds
to see small effects.

### Step 1 — see what clocks your GPU supports

```bash
nvidia-smi -q -d SUPPORTED_CLOCKS -i 0
```

(`-i 0` selects GPU 0; change the number if you want a different GPU.)

### Step 2 — enable persistence mode and lock clocks

Pick a graphics clock **well below the boost ceiling** so the GPU can
hold it under load without thermal throttling. Memory clock should be
the highest supported value.

```bash
sudo nvidia-smi -pm 1 -i 0
sudo nvidia-smi -lgc <graphics_clock_mhz> -i 0
sudo nvidia-smi -lmc <memory_clock_mhz>   -i 0
```

### Step 3 — when you're done benching, restore defaults

```bash
sudo nvidia-smi -rgc -i 0
sudo nvidia-smi -rmc -i 0
```

### Other knobs (rough order of impact)

- Pin to one GPU on multi-GPU boxes:
  ```bash
  export CUDA_VISIBLE_DEVICES=0
  ```
- No other CUDA processes on the same device while benching.
- No display server / compositor on the bench GPU.
- Set CPU governor to performance:
  ```bash
  sudo cpupower frequency-set -g performance
  ```

---

## How it works (skim if you're curious)

- **Current side** runs `cargo bench` directly in your main checkout,
  so your uncommitted edits are benched as-is and your warm `target/`
  cache is reused. No fresh CUDA build for the current side.
- **Ref side** runs in a persistent worktree under
  `sp1-gpu/.bench-worktrees/<ref>/`, reused across invocations so the
  second-run cost is small.
- Both sides are compiled with **one batched** `cargo bench --no-run`
  call per side. The captured bench binaries are then invoked directly
  per round, which avoids cargo's freshness check and any
  `sp1-gpu-sys` build-script reruns between rounds.
- Round `k` alternates which side runs first (odd: current → ref;
  even: ref → current) to de-bias against time-ordering effects.
- A small Python helper
  ([`_bench_compare_format.py`](_bench_compare_format.py)) reads
  Criterion's per-batch sample data from both `target/criterion/`
  trees, pools per-round samples, runs **Welch's t-test** on the
  difference in mean, and prints the side-by-side table.

---

## Getting help

```bash
sp1-gpu/scripts/bench-compare.sh --help
```

prints a condensed reference of the same options described above.
