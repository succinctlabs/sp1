// Device-side fold-metadata derivation for JaggedMle.
//
// Replaces the host-side `next_start_indices_and_column_heights` helper that
// downloaded `column_heights`, applied `h.div_ceil(4)*2` element-wise, and
// re-computed the exclusive prefix sum on host. Keeping that on host meant
// every fold paid a GPU→CPU sync (drain stream → memcpy → resume) plus the
// reverse host→device upload of the freshly computed metadata.
//
// One launch handles any n_columns: a multi-block decoupled-lookback
// inclusive scan with the `h.div_ceil(4)*2` transform fused into the load
// and the exclusive-prefix-shift fused into the store. Mirrors the pattern
// in `slop/.../scan.cuh::scan_large::Scan<T>`. Each block atomically claims
// a sequential block_id, scans its 512-element segment locally
// (Brent-Kung), waits on the previous block's published partial sum via
// `flags[bid]`, adds it to local results, and publishes its own updated
// tail for the next block.
//
// Caller responsibilities (mirroring the existing scan_large::Scan
// callers):
//   - `block_counter`: 1 u32, zeroed before launch.
//   - `flags`: n_blocks + 1 u32s; flags[0] = 1 (first block needs no wait),
//     flags[1..] = 0.
//   - `scan_values`: n_blocks + 1 u32s; scan_values[0] = 0 (first block's
//     "previous prefix" is zero).
//   - `new_column_heights`: n_columns u32s, uninit on entry.
//   - `new_start_indices`: n_columns + 1 u32s, uninit on entry.
// Launch grid_dim = ceil(n_columns / SECTION_SIZE), block_dim =
// `jagged_fold_metadata_block_dim()` (== SECTION_SIZE / 2).

#pragma once

#include <cstdint>

extern "C" void* jagged_fold_metadata_kernel();
extern "C" uint32_t jagged_fold_metadata_block_dim();
extern "C" uint32_t jagged_fold_metadata_section_size();
