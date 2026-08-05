// Per-chip geq correction for the DAG-native zerocheck.
//
// The main fused kernel used to subtract `geq(row, e) · pad_adj · eq[row] · λ`
// per row of each chip's carrier chunk. That sum is purely a function of the
// chip's padding parameters and the per-round `partial_lagrange`, so we hoist
// it out: this kernel computes, per chip, the closed-form contribution to
// each eval-point total and writes 3 ext_t partials (one per eval point)
// that the host aggregation sums alongside everything else.
//
// All inputs are device-resident:
//   - `geq_chip_indices` (shard-static): the chip indices that should get a
//     correction (filtered for `has_sequential && pad_adj != 0` at shard init).
//   - `geq_state` (per round): VirtualGeq state per chip, updated in place by
//     the `fix_geq_state` kernel after each fold. Indexed by chip_idx.
//   - `chip_pad_adj`, `powers_of_lambda` (shard-static): one ext per chip.
//   - `chip_layouts` (per round): provides `height` so we can derive
//     `in_limit = min(height / 2, 1 << rest_point_dim)` without a separate
//     row-count buffer.
//
// One block per geq-active chip. Each thread strides over the chip's
// `[0, in_limit)` row range summing the in-range eq values into two
// reductions; thread 0 forms `S(e) = A_z + ep·(A_o − A_z)` for
// `ep ∈ {0, 2, 4}` and writes `−λ · pad_adj · S(e)` so host aggregation
// adds it straight into totals[e].

#pragma once

#include "config.cuh"
#include "zerocheck/sequential.cuh"  // ChipLayout
#include <cstdint>

// Per-chip VirtualGeq state on device — mirror of `VirtualGeq<Ext>` in
// slop_multilinear and `VirtualGeqStateC` in zerocheck/src/prover.rs.
// Updated in place each round by `fix_geq_state`.
struct VirtualGeqState {
    uint32_t threshold;        // 4
    uint32_t num_vars;         // 4
    ext_t geq_coefficient;     // 16  (in practice always 1 from the initial new())
    ext_t eq_coefficient;      // 16
};

// Updates `state[chip_idx]` for every active chip in place, applying
// `VirtualGeq::fix_last_variable(alpha)`. One thread per chip.
extern "C" void* zerocheck_fix_geq_state_kernel();

// Per-chip geq corrections kernel. See file banner for the I/O contract.
extern "C" void* zerocheck_geq_corrections_kernel();

// Bivariate variant for the fused first-two-rounds: 12 partials per geq chip,
// one per non-boolean grid node. See zerocheck/bivariate.cuh for node order.
extern "C" void* zerocheck_geq_corrections_bivariate_kernel();
