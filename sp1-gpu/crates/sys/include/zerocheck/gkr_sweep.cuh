// Per-chip GKR column sweep, decoupled from the constraint kernel.
//
// Each round, every active chip contributes
//   Σ_row eq[row] · λ_chip · Σ_col gkr_powers[col] · trace[col, row, e]
// to the per-eval-point totals — the same value that used to be folded into
// the constraint kernel's "carrier chunk" inline. Moving it out lets us
// dimension the work to actually scale with chip width: a single thread per
// row can't do a 10k-column sweep in any reasonable time, so this kernel
// uses warp-per-row with lane-strided column reduction.
//
// Block layout: 256 threads = 8 warps. Each warp owns one row at a time
// and grid-strides through the tile's rows; within a row, 32 lanes
// parallel-stride over (main + prep) columns and warp-reduce into a single
// row total. The warp's lane 0 then weights by eq · λ and accumulates into
// a per-warp partial that the block reduces at the end.
//
// One block per (chip, row-tile). The launcher builds a `BlockDispatch`
// table with `chunk_id` overloaded as `chip_idx` — same shape as the
// sequential dispatch table, different semantics.
//
// Fixes the latent "ColumnTile-only chip never gets GKR" gap by treating
// every non-empty chip uniformly. The legacy `synthesize_gkr_chunk` /
// `is_gkr_carrier` ColumnTile fallback in `compile_chips` becomes dead
// weight — the launcher skips it.

#pragma once

#include "config.cuh"
#include "zerocheck/sequential.cuh"  // BlockDispatch, ChipLayout
#include <cstdint>

// Per-chip GKR widths. Indexed by chip_idx; shard-static (widths don't
// change between rounds). Mirrors `ChipGkrInfoC` in
// zerocheck/src/prover.rs.
struct ChipGkrInfo {
    uint32_t main_width;       // 4
    uint32_t prep_width;       // 4
};

// Block size (must match the launcher).
constexpr int GKR_SWEEP_BLOCK_SIZE = 256;
constexpr int GKR_SWEEP_WARPS_PER_BLOCK = GKR_SWEEP_BLOCK_SIZE / 32;

extern "C" void* zerocheck_gkr_sweep_kb_kernel();
extern "C" void* zerocheck_gkr_sweep_ext_kernel();
