// Device-side aggregation of per-block partials into the 3 per-eval-point
// totals.
//
// The fused-sequential kernel (and the geq + ColumnTile kernels) all write
// one ext_t per (block, eval point) into a flat `partials` buffer, laid out
// as `[block][e]` triples. This kernel sums them into three ext_t outputs in
// a single launch, so the host only downloads the 3 totals instead of the
// full O(blocks) array.
//
// Single block, grid-stride over triples; per-thread acc[3] reduced via
// `partialBlockReduce` once per eval point. n_blocks_total is bounded by
// the per-round dispatch table sizes (a few thousand on real workloads), so
// single-block + grid-stride is sufficient.

#pragma once

#include "config.cuh"
#include <cstdint>

// Reduces `total_slots / 3` block triples in `partials` into `totals[0..3]`.
// `total_slots` must be a multiple of 3.
extern "C" void* zerocheck_aggregate_partials_kernel();

// Strided variant for the fused first-two-rounds partials buffers: reduces
// `total_slots / stride` groups of `stride` slots into `totals[0..stride]`.
// Launched with gridDim.x == stride; `total_slots` must be a multiple of it.
extern "C" void* zerocheck_aggregate_partials_strided_kernel();
