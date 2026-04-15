---
name: sp1-profiling
description: Profile an SP1 zkVM program to find cycle-count hotspots. Use when the user asks to profile, find bottlenecks, see "where cycles go", or analyze performance of an SP1 program. Covers enabling the profiler, running it, and interpreting the Firefox-Profiler-format JSON without needing samply.
allowed-tools: Read, Grep, Glob, Bash, Edit, Write
---

# Profiling SP1 programs

SP1's profiler captures per-function cycle counts using the program's DWARF debug info and writes a Firefox-Profiler-format JSON. Each "sample" in the output is **one RISC-V cycle**, so sample counts equal cycle counts exactly.

Reference: https://docs.succinct.xyz/docs/sp1/optimizing-programs/profiling

## When to use this skill

- User asks to profile an SP1 program / find hotspots / analyze cycles.
- User wants to know where the bulk of `total_instruction_count()` is spent.
- User wants to validate a precompile is being used (e.g. Keccak, secp256k1, BN254).

## When *not* to use it

- Just measuring total cycles → call `client.execute(...)` and read `report.total_instruction_count()`. Don't enable profiling.
- Measuring proving time / GPU throughput → that's a separate benchmark, not profiling.

## Step 1 — Enable the `profiling` feature

In the script crate's `Cargo.toml`:

```toml
sp1-sdk = { version = "<your-version>", features = ["profiling", ...] }
```

The feature is **a no-op when `TRACE_FILE` isn't set**, so leave it on permanently — the same binary handles profiling and other runs without recompiling.

## Step 2 — Run with `TRACE_FILE` set

```bash
TRACE_FILE=profiles/<name>.json cargo run --release -- --execute ...
```

Notes:

- Must be `--execute` (or whatever invokes `client.execute(...)`), not `--prove`. Profiler hooks into the executor.
- Output files are large (often **>100MB for ~10M cycles**). Always write to a gitignored directory like `profiles/` — never to the repo root or workspace dirs. Confirm the destination directory exists; create it if not.
- For programs >100M cycles, set `TRACE_SAMPLE_RATE=100` (sample 1-in-N) to keep the file manageable.
- Build the program with debug info (default for SP1 programs); without it, frames will be raw addresses instead of demangled Rust names.
- A small input is usually enough. The profiler shows *proportions*, not absolute scaling, so 1–8 iterations of the workload typically gives the same hotspot picture as 1000.

## Step 3 — Analyze the JSON

The standard tool is `samply load <file>` (Firefox Profiler UI). For non-interactive analysis (CI, headless box, or quick reporting), parse the JSON directly — it's reasonably simple. **Always present both self-time and inclusive-time tables**: self-time tells you which leaf functions burn cycles, inclusive-time tells you which high-level operations contain that work.

Schema essentials (from one thread under `threads[0]`):

- `samples.data[i][0]` → stack id (one row per cycle).
- `stackTable.data[sid]` → `[prefix_stack_id, frame_id]` (linked list, walk via `prefix` to get the chain).
- `frameTable.data[fid][0]` → string-table index for the function name.
- `stringTable[idx]` → demangled-ish name (Rust mangling artifacts like `[hash]::` are present).

Drop-in Python analyzer:

```python
import json, sys
from collections import Counter

d = json.load(open(sys.argv[1]))
t = d['threads'][0]
strings, frames, stacks, samples = (
    t['stringTable'], t['frameTable']['data'],
    t['stackTable']['data'], t['samples']['data'],
)

def chain(sid):
    out = []
    while sid is not None:
        prefix, frame = stacks[sid]
        out.append(frame); sid = prefix
    return out

self_t, incl_t, total = Counter(), Counter(), 0
for s in samples:
    sid = s[0]
    if sid is None: continue
    total += 1
    c = chain(sid)
    self_t[c[0]] += 1
    for f in set(c):
        incl_t[f] += 1

def name(fi):
    loc = frames[fi][0]
    return strings[loc] if loc is not None else '?'

print(f"Total cycles: {total}\n=== SELF TIME (top 20) ===")
for f, c in self_t.most_common(20):
    print(f"  {c:>10} ({100*c/total:5.2f}%)  {name(f)[:140]}")
print("\n=== INCLUSIVE TIME (top 20) ===")
for f, c in incl_t.most_common(20):
    print(f"  {c:>10} ({100*c/total:5.2f}%)  {name(f)[:140]}")
```

Save as `analyze.py` (or run inline) and invoke with the trace path.

## Step 4 — Interpret the output

Read self-time and inclusive-time together:

- A function with high **inclusive** but low **self** time means its cost is in callees — drill in. Example: a top-level entry point is typically near-100% inclusive and near-0% self.
- A function with high **self** time is the literal bottleneck. Common culprits in zkVM workloads:
  - `memcpy` / `memset` → struct moves and zero-init; often the call site (one frame up the stack) is the real cost. Look at the types involved and consider passing by reference or reusing buffers.
  - `syscall_<precompile>` (e.g. `syscall_keccak_permute`, `syscall_secp256k1_add`) → the precompile is being used. Self-time **should be small** relative to syscall count; if it's large, suspect a missing patch or a non-precompiled fallback.
  - Repeated short-lived object setup (e.g. hasher state, allocators) → many small operations each pay driver overhead. Reuse instances (`reset()`) instead of creating new ones.
- Cross-check with `report.syscall_counts` from `client.execute(...)`. A near-zero count for a syscall you expected to fire means the relevant patched crate isn't being pulled in (verify via `cargo tree`).
- Normalize by the number of iterations in the input. Per-iteration cost is more meaningful than total. Cycles should scale linearly with iteration count; if not, there's amortization (good — note it) or a fixed-cost outlier (investigate).

## Reporting back to the user

Always include:

1. **Total cycles** and per-iteration cost.
2. **Top ~5 self-time entries** with percentages.
3. **Top ~5 inclusive-time entries** with percentages.
4. **One-paragraph interpretation**: where the time goes structurally, and the most actionable optimization target.
5. The path where the trace was written, so the user can run `samply load <file>` themselves.

Keep raw stack dumps out of the chat — they're long and low signal.
