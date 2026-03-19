# Jagged Assist GPU Implementation Notes

## Overview

The jagged assist GPU kernels implement a "precomputed prefix states + cached eval"
optimization for the jagged evaluation sumcheck. The key idea: instead of re-evaluating the
full branching program at every sumcheck round, we precompute all prefix states once (backward
DP), maintain a suffix vector on device, and combine them at each round.

## Architecture

### Branching Program (Width-8)

The width-8 branching program has 8 memory states (0-7) encoding `carry + (comparison_so_far << 1) + (saved_index_bit << 2)`, plus a FAIL state (8). It checks whether a trace index falls within a column's range.

Each layer of the branching program processes one bit. There are `2 * (max(z_row_len, z_index_len) + 1)` total layers:
- **Even layers** (0, 2, 4, ...): Process `z_row[k]`, `z_index[k]`, and `curr_prefix_sum[k]` where `k = layer / 2`. Use the `CURR_TRANSITIONS_W8[8][8]` table.
- **Odd layers** (1, 3, 5, ...): Process `next_prefix_sum[k]` where `k = layer / 2`. Use the `NEXT_TRANSITIONS_W8[2][8]` table.

Layers are numbered from 0 (LSB/bottom) upward. **Round 0 of the sumcheck processes layer 0.**

### Transition Table Indexing

`CURR_TRANSITIONS_W8[bit_state][memory_state]` where `bit_state = (curr_ps_bit << 2) | (index_bit << 1) | row_bit`.

`NEXT_TRANSITIONS_W8[bit_state][memory_state]` where `bit_state = next_ps_bit`.

### CUDA Kernels

All in `sp1-gpu/crates/sys/lib/jagged_assist/branching_program.cu`:

1. **`precomputePrefixStates`** — Backward DP from layer `num_layers-1` down to 0. Initializes success states at layer `num_layers`, then applies transitions backward. Stores per-layer states at `prefix_states[(layer * 8 + state) * num_columns + col]`.

2. **`evalWithCachedAtZeroAndHalf`** — Given a `round_num` (= layer), loads `prefix_states[layer+1]` and the current `suffix_vector`, applies a single layer transition at lambda=0 and lambda=1/2, dots prefix with suffix, and multiplies by the eq/z_col weights.

3. **`updateSuffixVector`** — Single-thread kernel. After the verifier samples alpha, applies the transposed layer step to update the suffix vector in-place on device.

### `computeThreeVarPartialLagrange(a, b, c)`

Computes the 8-entry partial Lagrange basis. **Output layout: `(a_bit << 2) | (b_bit << 1) | c_bit`** (the first argument is the MSB of the index). This must match the transition table indexing.

- In `precomputePrefixStates`: called as `(curr_ps_val, z_index_val, z_row_val)` → index = `(cps << 2) | (idx << 1) | row` ✓
- In `updateSuffixVector`: called as `(alpha, z_index_val, z_row_val)` → index = `(alpha << 2) | (idx << 1) | row` ✓

### Prefix Sum Access

Merged prefix sums are split into separate `current_prefix_sums` and `next_prefix_sums` arrays (column-major). The `getIthLeastSignificantValFromPoints(points, dim, col, num_cols, k)` helper accesses `points[(dim - k - 1) * num_cols + col]`.

## Key Files

| File | Purpose |
|------|---------|
| `crates/sys/include/jagged_assist/branching_program.cuh` | Width-8 transition tables, enums, constants |
| `crates/sys/lib/jagged_assist/branching_program.cu` | CUDA kernels |
| `crates/sys/src/jagged.rs` | FFI bindings (KernelPtr declarations) |
| `crates/jagged_assist/src/branching_program.rs` | `BranchingProgramKernel` trait, unit tests |
| `crates/jagged_assist/src/sumcheck_sum_as_poly.rs` | `JaggedAssistSumAsPolyGPUImpl` (launches kernels) |
| `crates/jagged_assist/src/sync_eval_sumcheck.rs` | `prove_jagged_evaluation_sync` entry point, e2e test |

CPU reference:
| File | Purpose |
|------|---------|
| `slop/crates/jagged/src/poly.rs` | `BranchingProgram`, `MemoryState`, `BitState`, transitions |
| `slop/crates/jagged/src/jagged_assist/sumcheck_sum_as_poly.rs` | `JaggedAssistSumAsPolyCPUImpl` |

## Bugs Found and Fixed (March 2026)

### 1. Layer ordering reversal
**Symptom:** GPU produced all-zero coefficients at round 0.
**Root cause:** Both `evalWithCachedAtZeroAndHalf` and `updateSuffixVector` used `layer = num_layers - 1 - round_num`, but the CPU maps `round_num` directly to layer (round 0 = layer 0).
**Fix:** Changed to `layer = round_num` in both kernels.

### 2. `computeThreeVarPartialLagrange` argument order
**Symptom:** Shard proof verification failure.
**Root cause:** The function was called as `(z_row, z_index, curr_ps)` producing layout `(row << 2) | (idx << 1) | cps`, but CURR_TRANSITIONS_W8 expects `(cps << 2) | (idx << 1) | row`.
**Fix:** Swapped first and third arguments to `(curr_ps, z_index, z_row)` in both `precomputePrefixStates` and `updateSuffixVector`.

### 3. test_transition memory state and bit ordering
**Symptom:** Assertion failure (left=0, right=4).
**Root cause:** Test used `all_memory_states()` (8 states) but GPU transition table has 5 (4+FAIL for width-4). Also, bit state ordering in the test didn't match the GPU enum.
**Fix:** Used `MemoryState::width4_states()` and corrected bit ordering to match GPU's `next_ps(bit0) | curr_ps(bit1) | index(bit2) | row(bit3)`.

## `evalWithCachedAtZeroAndHalf` Optimizations (March 2026)

The kernel evaluates the width-8 branching program at lambda=0 and lambda=1/2 for each column, combining precomputed prefix states with the suffix vector. The following optimizations reduce extension field multiplications by ~5×.

### 1. Direct sparse accumulation (eliminates dense dot product)

The transition table is very sparse: for each input memory state `ms`, only 2 out of 8 bit states produce non-FAIL transitions. The original code built a dense `accum_elems[8]` array and dotted it with `pstate[8]` (8 EF×EF mults, 6 wasted on zeros). The optimized code directly accumulates `two_var_eq[half_i] * pstate[out_ms]` for non-FAIL entries only.

### 2. Period-4 suffix sum trick (even layer only)

`CURR_TRANSITIONS_W8[bs][m] == CURR_TRANSITIONS_W8[bs][m+4]` for all `bs` and `m`, because the saved_index_bit (bit 2 of the state encoding) is passively carried through curr-layer transitions. This means `pstate[CURR_TRANS[bs][m]]` is identical for `m` and `m+4`. We precompute `ss[i] = suffix[i] + suffix[i+4]` (4 values) and loop over `m=0..3` instead of `ms=0..7`, halving the inner loop.

Combined with the transposed accumulation order (loop over `half_i` first, then `m`), the even-layer BP computation uses ~24 EF×EF mults instead of ~128.

**Note:** This symmetry does NOT hold for `NEXT_TRANSITIONS_W8` (odd layers), so the odd layer uses the full `ms=0..7` loop.

### 3. Reuse y_0 in y_half

For the "at half" evaluation, both `curr_ps=0` and `curr_ps=1` bit states contribute equally (weight `half` each). Since the `curr_ps=0` contribution is exactly `y_0`, we compute:
- `y_0` from curr_ps=0 transitions
- `y_one` from curr_ps=1 transitions
- `y_half_raw = y_0 + y_one` (no half factor yet)

The two half factors (BP half from `[1/2, 1/2]` base factors + eq_half from eq polynomial) are combined into `half_sq = half^2` and applied once at output.

### 4. Base field multiplies (F×EF instead of EF×EF)

Three values that are conceptually base field elements were previously wrapped in EF:
- `eq_zero = 1 - ps_val` where `ps_val` comes from `getIthLeastSignificantValFromPoints<F>()` — kept as `F eq_zero_base`
- `half` is `1/2` which lives in the base field — extracted via `F half_base = half.value[0]`
- `half_sq = half_base * half_base` — computed as F×F

F×EF multiplication is ~4× cheaper than EF×EF (4 base mults vs 16 + reduction).

### 5. Precompute common output factor

Both output lines multiply by `z_col_eq_val * intermed`. Computing `common = z_col_eq_val * intermed` once saves 1 EF×EF per column.

### 6. Suffix vector in shared memory

The 8-element suffix vector is identical across all columns. Loading it into `__shared__` memory once per block (128 bytes) avoids redundant global memory reads per thread.

### EF multiplication count summary (per column)

| Component | Original | Optimized |
|-----------|----------|-----------|
| Even layer BP (after_zero + after_half) | ~128 EF×EF | ~24 EF×EF |
| Odd layer BP (after_zero + after_half) | ~72 EF×EF | 16 EF×EF |
| Suffix dot products | 16 EF×EF | 0 (folded into transposed accum) |
| Output chain | 6 EF×EF | 3 EF×EF + 2 F×EF |

## Testing

- **Unit test:** `test_transition` in `branching_program.rs` — validates GPU transition tables against CPU `transition()` function
- **E2E test:** `test_gpu_vs_cpu_jagged_eval_sumcheck` in `sync_eval_sumcheck.rs` — runs full sumcheck on both CPU and GPU, compares all round polynomials
- **Integration:** `node.rs` in `sp1-gpu-perf` — full shard proving benchmark (requires GPU)
