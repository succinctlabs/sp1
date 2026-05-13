# Briefing: secp256k1 scalar-mul precompile perf comparison (remote run)

## Goal

Measure executor throughput of branch `rdalal/ecmul` against `main` on three RSP
guest workloads, using `sp1-perf-executor --mode minimal_trace`. The change being
measured: a new `SECP256K1_MUL` precompile path that replaces ECDSA recovery's
per-bit double-and-add loop with 2× `syscall_secp256k1_mul` + 1× `syscall_secp256k1_add`.

Local single-run numbers showed +18–29% executor MHz on ecmul. Remote run goal:
**3 to 5 runs per (branch, block) cell**, report mean ± stddev, on a quiet
machine.

## Inputs and current state

Work branch: `rdalal/ecmul` in the `succinctlabs/sp1` fork (already pushed to
origin). The branch contains, on top of `main`:

- `crates/zkvm/lib/src/secp256k1.rs` — the override that makes
  `multi_scalar_multiplication` use the new mul syscall (this is the core change
  under test).
- `crates/perf/src/bin/executor.rs` — `execute_minimal` extended to replay
  chunks through `GasEstimatingVMEnum` and print `ExecutionReport` including
  `syscall_counts`.
- `crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_mul.rs` —
  new chip with a placeholder `assert_bool` constraint (so machine construction
  passes the `max_constraint_degree > 0` assert).
- `crates/core/executor/src/artifacts/rv64im_costs.json` — placeholder cost
  entries for `Secp256k1MulAssign` / `Secp256k1MulAssignUser`.
- `examples/rsp/script/bin/dump_core_u64.rs` (new file) and
  `examples/rsp/script/Cargo.toml` (binary entry).
- `.gitignore` — adds `crates/perf/inputs/`.
- This briefing (`remote-perf-briefing.md`).

For the comparison: only the **sp1-lib override** and the **dump_core script**
matter for behavior. The chip + costs are needed for `--mode node` / `--mode gas`
but **`--mode minimal_trace`** is what we're measuring and doesn't touch them.

The `main` worktree won't have the dump_core script or the `executor.rs`
gas-replay code (they're additive changes on `rdalal/ecmul`), so the setup
step below copies them over.

## Setup on the remote

```bash
# Clone and check out the work branch:
git clone <sp1-repo-url> sp1 && cd sp1
git checkout rdalal/ecmul

# Create a detached worktree at main as the baseline:
git worktree add --detach ../sp1-bench-main main

# Copy the dump_core script and the executor.rs gas-replay change into the main
# worktree (they're additive and don't exist on main):
cp examples/rsp/script/bin/dump_core_u64.rs \
   ../sp1-bench-main/examples/rsp/script/bin/

# Append the [[bin]] entry to ../sp1-bench-main/examples/rsp/script/Cargo.toml:
#   [[bin]]
#   name = "dump_core_u64"
#   path = "bin/dump_core_u64.rs"

cp crates/perf/src/bin/executor.rs \
   ../sp1-bench-main/crates/perf/src/bin/executor.rs
```

The RSP input cache (`examples/rsp/script/input/1/{20526624,21740137,21740164}.bin`)
is tracked in git, so it's available after clone — no S3 fetch needed.

## Build (slow first time; both worktrees have separate target dirs)

```bash
# In sp1/ (rdalal/ecmul):
(cd examples/rsp/script && cargo build --release --bin dump_core_u64)
cargo build --release -p sp1-perf --bin sp1-perf-executor

# In sp1-bench-main/ (main):
(cd ../sp1-bench-main/examples/rsp/script && cargo build --release --bin dump_core_u64)
(cd ../sp1-bench-main && cargo build --release -p sp1-perf --bin sp1-perf-executor)
```

## Dump inputs (one-time per branch)

`dump_core_u64` reads `examples/rsp/script/input/<chain>/<block>.bin` and writes
`crates/perf/inputs/rsp-core-u64/<chain>/<block>/{program.bin,stdin.bin}`. ELFs
differ slightly between branches (~31 kB) because the guest is rebuilt against
each branch's `sp1-zkvm`. Dump on **both** branches:

```bash
for root in /path/to/sp1 /path/to/sp1-bench-main; do
  (cd $root/examples/rsp/script && \
   for blk in 20526624 21740137 21740164; do
     ./../../target/release/dump_core_u64 --block-number $blk
   done)
done
```

## Perf runs

Run **each (branch × block) cell N times**, N=3 minimum, 5 preferred. Interleave
runs across branches/blocks rather than batching by cell — that way thermal
state and any system drift affect all cells roughly equally:

```bash
mkdir -p /tmp/perf_results
N=5
for i in $(seq 1 $N); do
  for blk in 20526624 21740137 21740164; do
    for variant in main ecmul; do
      [ "$variant" = "main" ] && root=/path/to/sp1-bench-main || root=/path/to/sp1
      $root/target/release/sp1-perf-executor --local \
        --program $root/crates/perf/inputs/rsp-core-u64/1/$blk/program.bin \
        --param   $root/crates/perf/inputs/rsp-core-u64/1/$blk/stdin.bin \
        --mode minimal_trace 2>&1 | tail -80 \
        > /tmp/perf_results/${variant}_${blk}_run${i}.txt
    done
  done
done
```

## What to extract from each run

Per-run output lines look like:

```
exit code: 0, cycles: 295034080
execution time: 2.018857834s
mhz: 146.13910649441007
gas: 345335481
syscall counts (...): ...
```

Per cell, collect across runs: cycles (should be deterministic; sanity check),
execution time (s), MHz, gas. Compute **mean and stddev**. Cycles should be
identical across runs of the same cell.

## Expected results (from preliminary local single-run data)

| Block | Recoveries | metric | main → ecmul | local Δ |
|---|---:|---|---|---|
| 20526624 | 41 | time / MHz | 568.9 ms / 101.9 → 445.2 ms / 128.2 | **−21.7% / +25.8%** |
| 21740164 | 139 | time / MHz | 2.455 s / 121.4 → 2.019 s / 146.1 | **−17.8% / +20.3%** |
| 21740137 | 414 | time / MHz | 5.840 s / 102.9 → 4.445 s / 133.1 | **−23.9% / +29.3%** |

Syscall counts should show: doubles 0 on ecmul (entirely eliminated), adds
dropping from ~256× recoveries to 1× recoveries, muls = 2× recoveries (e.g.
278 muls + 139 adds for block 21740164).

Gas: ecmul ~2% lower than main, but this is **artificially favorable** — the
`Secp256k1MulAssign` chip cost is a placeholder. Don't read too much into the
gas comparison.

## Reporting to Notion

There is an existing Notion page that should receive the multi-run results:

- **Parent page:** "EC MUL Perf reports"
- **Parent page URL:** https://www.notion.so/succinctlabs/EC-MUL-Perf-reports-35fe020fb42f80bbaf8bc01533a13337
- **Parent page ID:** `35fe020f-b42f-80bb-af8b-c01533a13337`
- Already has one child page from local single-run data; create a **new sibling
  child page** under the same parent for the remote multi-run results so the
  earlier preliminary results stay intact.

### Notion MCP setup (one-time on the remote machine)

The remote agent's Claude Code instance won't have Notion access by default.
Setup steps:

```bash
# Register the hosted Notion MCP server with Claude Code:
claude mcp add --transport http notion https://mcp.notion.com/mcp

# Restart Claude Code on the remote so the MCP loads on next session start.
# Verify:
claude mcp list   # should show: notion - https://mcp.notion.com/mcp - ✓ Connected
```

On the first invocation of any `mcp__notion__*` tool, the remote will trigger
an OAuth flow in a browser. Sign in to the same Notion workspace
(`succinctlabs`) and authorize. The parent page above must be visible to the
integration; since OAuth on this workspace was granted broadly, that should
just work — sanity-check with `mcp__notion__notion-search` against a known
title before attempting to write.

### Creating the results page

Once Notion is wired up, create a new child page using
`mcp__notion__notion-create-pages` with:

```json
{
  "parent": { "type": "page_id", "page_id": "35fe020f-b42f-80bb-af8b-c01533a13337" },
  "pages": [{
    "properties": { "title": "secp256k1 scalar-mul perf — remote N-run averages" },
    "icon": "📊",
    "content": "<markdown body>"
  }]
}
```

For the content body, follow the Notion-flavored Markdown spec available via
the MCP resource `notion://docs/enhanced-markdown-spec` (use
`ReadMcpResourceTool` with `server: "notion"`, `uri: "notion://docs/enhanced-markdown-spec"`).
Notion tables use a special XML-ish syntax in that flavor, not pipe-tables —
the spec covers it.

The page should include:

1. **Headline table:** for each (block, metric) pair: main mean ± σ, ecmul mean
   ± σ, Δ, and a "significant?" flag (Δ ≥ 2σ is a reasonable rule of thumb).
2. **Syscall counts** confirming the new path fires the expected
   2× muls + 1× add per ECDSA recovery on every ecmul cell.
3. **Run methodology:** N runs per cell, interleaving order, machine specs
   (CPU model, fixed frequency or not, OS, kernel).
4. **Caveats** preserved from the local notes: ELFs differ slightly between
   branches, gas comparison is flattered by placeholder mul-chip cost,
   minimal_trace excludes node-pipeline overhead.

## Caveats / pitfalls

- **Make the machine quiet** — close everything, no other heavy processes. CPU
  frequency scaling and thermal throttling will skew time/MHz; ideally pin
  frequency or use a server with fixed clocks.
- The build pulls ~10–15 GB of crates and compiles SP1 + reth + RSP deps; first
  build is 10–30 min on a fast machine.
- If `cargo` or the executor panics on memory-map errors, check the system's
  `vm.max_map_count` (Linux) is high enough; `sp1-perf-executor` mmaps trace
  chunks per shard.
- `--mode gas` and `--mode node` exist but **don't use them for the
  comparison** — gas will be flattered by the placeholder mul-chip cost; node
  mode pays for the splicing pipeline that isn't under test here.
- The RSP guest is built from a pinned git rev (`succinctlabs/rsp` @ `3647076`);
  don't change that.
