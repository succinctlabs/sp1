// Per-chip geq correction + per-round VirtualGeq state update.
//
// See `geq_corrections.cuh` for the full algorithm description. The math is
// an exact algebraic rearrangement of the per-row subtraction that used to
// live in `sequential.cu`, so the result is bit-identical modulo summation
// order (and since ext_t add is commutative + associative, even that
// doesn't matter).

#include "zerocheck/geq_corrections.cuh"
#include "zerocheck/sequential.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

// ============================================================================
// fix_geq_state — apply `VirtualGeq::fix_last_variable(alpha)` per chip.
//
// One thread per chip. Reads state[chip_idx], computes the new threshold and
// eq_coefficient via the closed-form recurrence, writes the result back.
// Matches `slop_multilinear::VirtualGeq::fix_last_variable` bit-for-bit.
// ============================================================================
__global__ void zerocheck_fix_geq_state(
    VirtualGeqState* __restrict__ state,
    uint32_t n_chips,
    ext_t alpha
) {
    uint32_t chip_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (chip_idx >= n_chips) {
        return;
    }
    VirtualGeqState s = state[chip_idx];
    // Host `VirtualGeq::fix_last_variable` panics on `num_vars == 0`; do
    // the same here so divergence between host and device semantics fails
    // loudly rather than silently mutating threshold/eq_coefficient on
    // exhausted state. See review bug #5.
    if (s.num_vars == 0u) {
        __trap();
    }
    uint32_t new_threshold = s.threshold >> 1;
    // The host-side formula:
    //   new_eq = (1 - alpha) * eq_coef           if threshold is even
    //   new_eq = alpha * (eq_coef + geq_coef) - geq_coef   if threshold is odd
    ext_t new_eq;
    if ((s.threshold & 1u) == 0u) {
        new_eq = (ext_t::one() - alpha) * s.eq_coefficient;
    } else {
        new_eq = alpha * (s.eq_coefficient + s.geq_coefficient) - s.geq_coefficient;
    }
    state[chip_idx].threshold = new_threshold;
    state[chip_idx].eq_coefficient = new_eq;
    state[chip_idx].num_vars = s.num_vars - 1;
}

// ============================================================================
// geq_corrections — per-chip closed-form correction summed in one kernel.
// ============================================================================
__global__ void zerocheck_geq_corrections(
    const uint32_t* __restrict__ geq_chip_indices,
    uint32_t n_geq_chips,
    const VirtualGeqState* __restrict__ geq_state,
    const ext_t* __restrict__ chip_pad_adj,
    const ext_t* __restrict__ powers_of_lambda,
    const ChipLayout* __restrict__ chip_layouts,
    const ext_t* __restrict__ partial_lagrange,
    uint32_t rest_point_dim,
    ext_t* __restrict__ partials  // 3 slots per geq chip, laid out as [idx][e]
) {
    const uint32_t out_idx = blockIdx.x;
    if (out_idx >= n_geq_chips) {
        return;
    }
    const uint32_t chip_idx = geq_chip_indices[out_idx];
    const VirtualGeqState s = geq_state[chip_idx];
    const ext_t pad_adj = ext_t::load(chip_pad_adj, chip_idx);
    const ext_t lambda = ext_t::load(powers_of_lambda, chip_idx);
    const ChipLayout lay = chip_layouts[chip_idx];

    // Effective row span for this chip in this round.
    const uint32_t row_limit = 1u << rest_point_dim;
    const uint32_t chip_row_count = lay.height / 2u;
    const uint32_t in_limit = chip_row_count < row_limit ? chip_row_count : row_limit;

    // Sum eq[row_idx] over rows where the (z|o)_idx > threshold, with the
    // (geq_coef + eq_coef) boost when the index hits the threshold and the
    // implicit `+ geq_coef` for indices > threshold. We carry geq_coef
    // through symbolically so the math works even if a future change
    // introduces non-unit geq_coef.
    ext_t thread_z = ext_t::zero();
    ext_t thread_o = ext_t::zero();
    for (uint32_t row_idx = threadIdx.x; row_idx < in_limit; row_idx += blockDim.x) {
        ext_t lagr = ext_t::load(partial_lagrange, row_idx);
        uint32_t z_idx = row_idx << 1;
        uint32_t o_idx = z_idx | 1u;
        if (z_idx > s.threshold) {
            thread_z += lagr * s.geq_coefficient;
        } else if (z_idx == s.threshold) {
            thread_z += lagr * (s.geq_coefficient + s.eq_coefficient);
        }
        if (o_idx > s.threshold) {
            thread_o += lagr * s.geq_coefficient;
        } else if (o_idx == s.threshold) {
            thread_o += lagr * (s.geq_coefficient + s.eq_coefficient);
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    ext_t A_z = partialBlockReduce(block, tile, thread_z, shared);
    block.sync();
    ext_t A_o = partialBlockReduce(block, tile, thread_o, shared);

    if (threadIdx.x == 0) {
        // S(e) = A_z + ep·(A_o − A_z) for ep ∈ {0, 2, 4}. Add doublings
        // (same diff trick as elsewhere) avoid felt-by-ext mults.
        ext_t diff = A_o - A_z;
        ext_t d2 = diff + diff;
        ext_t S0 = A_z;
        ext_t S1 = A_z + d2;
        ext_t S2 = A_z + d2 + d2;

        // Each chip subtracts `λ · pad_adj · S(e)` from totals[e]. Host
        // aggregation ADDS our slots, so we write the negation.
        ext_t coeff = lambda * pad_adj;
        const uint32_t base = out_idx * 3u;
        ext_t::store(partials, base + 0u, ext_t::zero() - coeff * S0);
        ext_t::store(partials, base + 1u, ext_t::zero() - coeff * S1);
        ext_t::store(partials, base + 2u, ext_t::zero() - coeff * S2);
    }
}

}  // namespace

extern "C" void* zerocheck_fix_geq_state_kernel() {
    return (void*)zerocheck_fix_geq_state;
}

extern "C" void* zerocheck_geq_corrections_kernel() {
    return (void*)zerocheck_geq_corrections;
}
