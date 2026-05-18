# Zerocheck-eval follow-up notes (out-of-repo)

Context: companion to the identity-fold prototype landed in `sp1-gpu/crates/air/`
on branch `identity-fold-symbolic-builder`. The analyzer that motivated this
(now removed) lived in `crates/air/src/bin/analyzer.rs` on the same branch
before cleanup; reconstruct from git if needed.

Covers two follow-up threads:
1. **Hash-cons** — additional instruction-count savings beyond identity-fold.
2. **Late-round latency / BlockAir coverage** — the small-round (15-18 trailing
   sumcheck rounds) latency that scales with the most expensive single-block
   chip program, currently BLS12-381 EC ops at ~85-94k instrs.

## What identity-fold captured

- New baseline (with side-table identity-fold): 1,580,213 instrs, max `f_ctr` 483, **MEMORY_SIZE tier 512**.
- Old baseline: 1,698,793 instrs, max `f_ctr` 534, **MEMORY_SIZE tier 1024**.
- Win: −7% instructions, one MEMORY_SIZE tier down (the leveraged occupancy lever — `Block Limit Registers = 4` from the Nsight profile).

## What hash-cons could capture (analyzer projection)

Re-running the analyzer's `fold-only` pass *on top of* the new builder output produced:

- 1,224,388 instrs, max `f_ctr` 332. Tier already 512 (same as baseline).
- That's an **additional −22% on instructions** beyond what identity-fold alone reaches.

The 22% comes from two things the typed Rust builder can't easily express:

1. **Operand dedup in the SSA stream**: the simulator unifies `Var(variant, idx)` and `Const(idx)` into a single tag namespace. Once a Var is referenced, every later use of the same Var (across different `SymbolicExprF` operand positions) routes through the same tag. The builder currently allocates a *fresh* vreg per `From<SymbolicVarF>` call.
2. **Cascading folds**: when an arithmetic op simplifies, its tagged result feeds back into downstream sigs. The simulator can dedup `(Mul, var_tag, one_tag) → var_tag`, then a later `(Add, x, var_tag)` benefits from the deduped var. The Rust builder loses this because each "var-as-Expr" is a fresh vreg.

## Why naive hash-cons hurts `f_ctr`

The first analyzer run measured hash-cons-only (do_hc=true, do_fold=false): −32% instructions, **but `f_ctr` went up from 534 → 762** (kept tier 1024). Reason: hash-cons shares vregs across uses. The linear-scan allocator in `optimizer.rs` can't free a vreg until its *last* use, so dedup-shared vregs have program-spanning live ranges. The instruction win was real; the register-pressure win was negative.

The identity-fold prototype deliberately avoids this by *not* sharing vregs — each `assign_const_f` / `assign_var_f` allocates fresh, and side-tables only record "this vreg is known zero/one" for fold detection. That's why baseline `f_ctr` dropped (534 → 483) while a naive hash-cons would have pushed it to 762.

## Paths forward

Three options, roughly in increasing scope:

### A. Lazy `SymbolicExprF` enum (recommended)

Change `SymbolicExprF` from `pub struct SymbolicExprF(pub u32)` to:

```rust
pub enum SymbolicExprF {
    Vreg(u32),
    Var(SymbolicVarF),
    Const(F),
}
```

Arithmetic operators dispatch on the kind of each operand and emit V-form / C-form / E-form opcodes inline without an explicit `FAssignV` / `FAssignC` first. Only operations that genuinely need a vreg (`FAssertZero`, the EE-form when both operands are vregs, etc.) trigger a materialization.

This mirrors what the simulator does and should capture the additional 22% without needing a smarter register allocator. The cost is touching every binary-op impl, the `AbstractField` impl, and any downstream caller that pattern-matches `SymbolicExprF(_)`. Searchable risk surface: `SymbolicExprF(`, `.data()`, `.0`.

Estimate: 1-2 days including downstream fix-ups.

### B. Scoped hash-cons with a sliding window

Keep the current `SymbolicExprF(u32)` shape; add a hash-cons cache in the symbolic builders keyed by `(opcode, canonical operand vregs)`. **Cap the cache to the last K = 64-256 instructions** to bound live-range extension. When `K` is small enough, the live-range hit stays below the instruction-count benefit.

The analyzer can be extended to sweep this window size and find the sweet spot empirically; predict somewhere in the 64-128 range. Result will likely fall between (identity-fold only) and (full hash-cons), tier-wise probably stays 512.

Estimate: ~half day. Lower upside than A, but lower risk and could compose with A later.

### C. Smarter register allocator

Replace `optimizer.rs`'s linear scan with something that handles overlapping ranges better:
- Live-range splitting: cut a long-lived vreg into multiple pieces at chosen split points, allowing reuse in between.
- Graph coloring: standard interference-graph approach, O(n²) but n is bounded.
- Or just a smarter linear scan with "spill-and-reuse" instead of "hold forever".

This makes (full) hash-cons safe by neutralizing the live-range issue, after which we could remove identity-fold's deliberate no-share constraint.

Estimate: 1-2 days for live-range splitting; longer for graph coloring. Highest upside ceiling — could capture the full 22% — but the most invasive change.

## Recommended order

1. Lock in the identity-fold win (this branch).
2. Validate on a GPU box (`cargo test --release -p sp1-prover test_e2e_node`) — confirm tier drop translates to occupancy improvement on actual Nsight numbers.
3. Pick A if the projected 22% extra instructions matters at the chip level (BLS / EC chips would benefit most). Pick B as a quick experiment first if A feels too invasive.
4. C only if A still leaves `f_ctr` higher than desired (e.g., if we discover the next tier boundary at 256 matters).

## Concrete patterns to look for in the analyzer

Things hash-cons specifically catches that identity-fold misses:

- `is_real * X` repeated across multiple constraints with the same `X` (only Var-side dedup catches the `is_real` reuse).
- Limb arithmetic in EC/BLS chips where the same coefficient products show up in numerator and denominator.
- `xor3_gen` in Keccak: the rotated `c[x][z]` index is structurally repeated across rounds.

Search budget for measurement: add a per-pattern fire counter to the simulator's hash-cons branch and run on each chip; the chips with the largest hash-cons savings are where lazy-`SymbolicExprF` will pay off most.

---

# Late-round latency: BlockAir coverage + dynamic dispatch

## Problem

In the late ~15-18 zerocheck rounds the kernel duration is bound by the longest single-thread program — one row × one air-block of the most expensive chip. Today that's BLS12-381 EC ops:

| chip | instrs | air blocks | instrs/block |
|---|---:|---:|---:|
| Bls12381AddAssign{,User} | 84-85k | **1** | 84-85k |
| Bls12381DoubleAssign{,User} | 93-94k | **1** | 93-94k |
| Bls12381Fp2MulAssign | 60k | **1** | 60k |
| Bls12381Fp2AddSubAssign | 37k | **1** | 37k |
| Bn254DoubleAssign | 46k | **1** | 46k |
| Bn254Fp2MulAssign | 30k | **1** | 30k |
| Secp256r1DoubleAssign | 41k | **1** | 41k |
| Secp256k1DoubleAssign | 50k | **12** | ~4k |
| KeccakPermute | 63k | **11** | ~6k |

Secp256k1 and Keccak are blocked; BLS / Bn254 / Secp256r1 / Fp2* / FpOp are
all single-block. Small-round latency scales with the longest single-thread
program, so the 94k BLS Double is the binding straggler. Projected scenario
with the full chip set was 65ms × ~18 short rounds ≈ 1.2s — vs ~21ms × ~7
early rounds ≈ 150ms.

## Step 1: cheap dispatch fix (~20 LOC)

`BlockAir<…> for WeierstrassAddAssignChip<E, M>` (11 blocks) and
`BlockAir<…> for WeierstrassDoubleAssignChip<E, M>` (12 blocks) in
`crates/air/src/air_block.rs` are already generic over the curve `E`.
They're used for Secp256k1 today. The only thing missing is dispatch in
`RiscvAir::eval_block` / `num_blocks`:

```rust
match self {
    RiscvAir::KeccakP(c) => c.eval_block(builder, i),
    RiscvAir::Secp256k1Add(c) | RiscvAir::Secp256k1AddUser(c) => c.eval_block(...),
    RiscvAir::Secp256k1Double(c) | RiscvAir::Secp256k1DoubleUser(c) => c.eval_block(...),
    // ADD: Secp256r1Add{,User}, Secp256r1Double{,User},
    //      Bn254Add{,User}, Bn254Double{,User},
    //      Bls12381Add{,User}, Bls12381Double{,User}
    _ => { assert!(i == 0); self.eval(builder); }
}
```

Expected effect:
- BLS Double single-thread program: 94k → ~8k per block. Small-round latency
  for BLS-bound case ~10× faster.
- New straggler becomes whichever non-blocked chip has the largest single-block
  program. From the table: Bls12381Fp2Mul at 60k, then Bn254/Bls12381 Fp2AddSub
  and FpOp at 30-37k. Each needs its own `BlockAir` impl (no shared generic) —
  partition by Fp coordinate / Karatsuba product / FieldOp respectively.

## Step 1.5: custom BlockAir for Fp2 / FpOp chips

After step 1, the longest single-block chip is `Bls12381Fp2MulAssign` at 60k.
Reasonable splits (each a few-block decomposition by sub-operation):

| chip | natural split | est blocks |
|---|---|---:|
| Bls12381Fp2MulAssign | Karatsuba: ac, bd, (a+b)(c+d), and combiners; range checks at end | 4-6 |
| Bn254Fp2MulAssign | same shape | 4-6 |
| Bls12381Fp2AddSubAssign | one block per Fp coordinate + range checks | 2-3 |
| Bls12381FpOpAssign | one block per FieldOp variant gate + result | 3-4 |

Pattern to follow: the existing `BlockAir for WeierstrassAddAssignChip` decomposition.
Each block borrows the relevant cols, calls one `FieldOpCols::eval_*` group, asserts
the relevant constraints. Run the analyzer (or its successor) on each before/after
to verify the longest block lands in the target range.

## Step 2: large-round cost analysis

BlockAir multiplies a chip's contribution to `total_len` by `N_blocks`. Each
air-block reloads its referenced columns; shared columns (`is_real`, input
limbs) get reloaded `N_blocks` times.

For the Secp256k1-shape decomposition (each block reads ~5-10 cols from a
~50-col chip), per-row column-loads go ~52 → ~66 (+27% memory traffic on
BLS rows). BLS rows are some fraction of `total_len` — call it 10% as a
typical estimate, so global DRAM pressure rises ~3%.

Early-round profile is already at 81% DRAM throughput → 81% × 1.03 ≈ 84%.
Still memory-bound, marginally slower duration (linear with reads). Net for
step 1 alone: ~3% early-round slowdown, ~10× small-round speedup. Strong
positive at the projected workload.

## Step 3: dynamic dispatch (eliminates the early-round cost)

If the 3% early-round cost from step 2 is unacceptable, switch the work-item
shape per round.

Idea: maintain *two* `JaggedDenseInfo` + program-index tables per chip set:
- **flat**: one item per chip-row, runs the chip's full `eval()` program.
- **blocked**: `num_blocks` items per chip-row, each runs one air-block's program.

Both tables share the underlying column data (the `JaggedTraceMle`); only the
work-item descriptor and program indices differ. Both tables are built once at
chip-set initialization (codegen runs twice — once per shape).

Per round, host picks based on `total_len` vs an occupancy-threshold:

```rust
let target_items = num_sms * target_occupancy_blocks * threads_per_block;
let info = if total_len >= target_items { &info_flat } else { &info_blocked };
```

For an L40 / Ada (128 SMs, ~6 blocks/SM achievable at 64 regs/thread, 256
threads/block): target_items ≈ 200k. Above that we're saturated either way →
flat (cheaper memory). Below → blocked.

Implementation:
1. Extend `EvalProgramInfo` to hold two variants (flat / blocked). Codegen
   `codegen_cuda_eval` already iterates blocks; emit both forms in one pass.
2. Extend `ZeroCheckJaggedPoly` to hold both `JaggedDenseInfo` (flat &
   blocked) along with the row-count metadata needed for both.
3. `evaluate_zerocheck` picks which info+program to pass to the kernel based
   on the current `total_len`.
4. `zerocheck_fix_last_variable` propagates the row halving on *both* info
   tables.

Estimate: 1-2 days. Largely host-side plumbing; kernel is unchanged.

## Step 4: intra-block parallelism (only if 1-3 aren't enough)

For *very* late rounds (`total_len < N_chips × num_air_blocks_avg`), the bottleneck
is still per-program latency — each program runs in one thread serially. Two
sub-options:

a) **Cooperative threads on one program**: Partition the constraint sum across
   multiple threads of a warp, reduce α-weighted contributions at the end.
   Works because `FAssertZero` accumulates α^i × expr_i — splittable. Requires:
   - Per-thread constraint-index range stored alongside the program.
   - Warp-level reduction on `folder.accumulator` before the final shfl-and-add.
   - Care with register-file sharing — splitting a program across 32 threads
     means each thread uses ~`MEMORY_SIZE / 32` registers. Could regain
     occupancy on the same program.

b) **Bespoke tail kernel**: For the last K rounds (where total_len << grid),
   ditch the 256-block-x floor and shrink the grid. Or batch the last K
   univariate evaluations into one launch (each round's univariate doesn't
   depend on the prior round's challenger output until after — but the
   *fixed-variable* substitution does. Limited fusion potential here unless
   we speculate on challenger values, which we can't.)

Both are bigger refactors. Defer unless the projected late-round latency
after steps 1-3 is still problematic.

## Recommended order (revisits the earlier list)

1. **Lock in identity-fold** (done, on `identity-fold-symbolic-builder`).
2. **Validate on GPU**: `cargo test --release -p sp1-prover test_e2e_node`,
   confirm correctness + measure tier-drop occupancy improvement on Nsight.
3. **Step 1: dispatch arms for Bn254/Bls12381/Secp256r1 Add+Double.**
   Smallest change with biggest projected late-round win. Re-profile small
   and large rounds; quantify large-round cost.
4. **If small-round latency is still bound by Fp2/FpOp chips after step 1**:
   add BlockAir for those (step 1.5). Custom per chip; ~half-day each.
5. **If large-round cost from steps 3-4 exceeds budget**: dynamic dispatch
   (step 3). 1-2 days.
6. **If late-round latency is still meaningful after 3-5**: intra-block
   parallelism (step 4). Significant refactor; only if the math demands it.
7. **Pursue the hash-cons / lazy-`SymbolicExprF` work** (top half of this
   doc) independently — it composes orthogonally with the latency work and
   targets the per-thread compute cost rather than the parallelism shape.
