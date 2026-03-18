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

## Testing

- **Unit test:** `test_transition` in `branching_program.rs` — validates GPU transition tables against CPU `transition()` function
- **E2E test:** `test_gpu_vs_cpu_jagged_eval_sumcheck` in `sync_eval_sumcheck.rs` — runs full sumcheck on both CPU and GPU, compares all round polynomials
- **Integration:** `node.rs` in `sp1-gpu-perf` — full shard proving benchmark (requires GPU)
