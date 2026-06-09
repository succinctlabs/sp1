// Device-side `ChipLayoutC` derivation for zerocheck.
//
// After `jagged_fold_metadata` updates `column_heights` and `start_indices`
// on device, this kernel reads them at the sparse per-chip positions and
// writes the per-chip trace pointers + heights into `chip_layouts`. One
// thread per chip — n_chips is tiny relative to n_columns, so a single
// small block per shard handles every realistic case.
//
// Shard-static inputs (uploaded once at shard init): one
// `ChipColumnLayoutEntry` per chip giving the column indices of the chip's
// prep / main sections in `column_heights`. Per-round inputs are the
// device-resident `start_indices` and `column_heights`.
//
// Replaces the host-side chip_layouts derivation entirely — downstream
// kernels read `chip_layouts[chip_idx]` directly; the host only needs
// `chip_heights[idx]` for dispatch building, and that's tracked via a
// shard-local per-chip recurrence (no GPU round-trip).

#pragma once

#include "zerocheck/sequential.cuh"  // ChipLayout
#include <cstdint>

// Per-chip column indices + widths, uploaded once per shard. Layout matches
// `ChipColumnLayoutEntry` on the Rust side.
struct ChipColumnLayoutEntry {
    uint32_t prep_col_idx;   // column index of the chip's first prep column
    uint32_t main_col_idx;   // column index of the chip's first main column
    uint32_t prep_width;     // 0 if the chip has no prep columns
    uint32_t main_width;     // 0 if the chip has no main columns
};

extern "C" void* jagged_chip_layouts_kernel();
