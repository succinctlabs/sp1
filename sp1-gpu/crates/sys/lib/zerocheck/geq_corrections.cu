// Per-chip geq correction + per-round VirtualGeq state update.
//
// See `geq_corrections.cuh` for the full algorithm description. The math is
// an exact algebraic rearrangement of the per-row subtraction that used to
// live in `sequential.cu`, so the result is bit-identical modulo summation
// order (and since ext_t add is commutative + associative, even that
// doesn't matter).

#include "zerocheck/geq_corrections.cuh"
#include "zerocheck/bivariate.cuh"
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
    // The launcher sizes `gridDim.x` exactly to `n_geq_chips`, so
    // `out_idx < n_geq_chips` always. Kept as a parameter for symmetry
    // with the data buffers; not bounds-checked here.
    (void)n_geq_chips;
    const uint32_t out_idx = blockIdx.x;
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

// ============================================================================
// geq_corrections_bivariate — the padded-row correction for the fused
// first-two-rounds evaluation.
//
// Rows are consumed in quadruples; the geq indicator restricted to a
// quadruple is bilinear in the last two variables, so its eq-weighted sum is
// determined by the four corner sums
//   A_c = Σ_quad eq[quad] · g(4·quad + c),   c = 2X + Y ∈ {0, 1, 2, 3},
// where `g(idx)` is the VirtualGeq vector value (0 below the threshold,
// eq+geq at it, geq above it). Thread 0 bilinearly extends the corner sums
// to the 12 non-boolean grid nodes and writes `−λ · pad_adj · S(node)`,
// aligned with the constraint kernel's node order. The boolean corners get
// NO correction: there the padded rows' constraint values are not summed by
// any kernel, and the two cancel exactly.
// ============================================================================
__global__ void zerocheck_geq_corrections_bivariate(
    const uint32_t* __restrict__ geq_chip_indices,
    uint32_t n_geq_chips,
    const VirtualGeqState* __restrict__ geq_state,
    const ext_t* __restrict__ chip_pad_adj,
    const ext_t* __restrict__ powers_of_lambda,
    const ChipLayout* __restrict__ chip_layouts,
    const ext_t* __restrict__ partial_lagrange,
    uint32_t rest_point_dim,
    ext_t* __restrict__ partials  // 12 slots per geq chip, laid out as [idx][e]
) {
    (void)n_geq_chips;
    const uint32_t out_idx = blockIdx.x;
    const uint32_t chip_idx = geq_chip_indices[out_idx];
    const VirtualGeqState s = geq_state[chip_idx];
    const ext_t pad_adj = ext_t::load(chip_pad_adj, chip_idx);
    const ext_t lambda = ext_t::load(powers_of_lambda, chip_idx);
    const ChipLayout lay = chip_layouts[chip_idx];

    // Effective quadruple span for this chip — must match the constraint
    // kernel's dispatch (ceil(height / 4) quadruples). Fully virtual
    // quadruples beyond it cancel identically and are summed by neither.
    const uint32_t quad_limit = 1u << rest_point_dim;
    const uint32_t chip_quad_count = (lay.height + 3u) / 4u;
    const uint32_t in_limit = chip_quad_count < quad_limit ? chip_quad_count : quad_limit;

    ext_t t00 = ext_t::zero();
    ext_t t01 = ext_t::zero();
    ext_t t10 = ext_t::zero();
    ext_t t11 = ext_t::zero();
    for (uint32_t quad_idx = threadIdx.x; quad_idx < in_limit; quad_idx += blockDim.x) {
        ext_t lagr = ext_t::load(partial_lagrange, quad_idx);
        const uint32_t base_idx = quad_idx << 2;
#pragma unroll
        for (uint32_t c = 0; c < 4u; c++) {
            const uint32_t idx = base_idx | c;
            ext_t contrib = ext_t::zero();
            if (idx > s.threshold) {
                contrib = lagr * s.geq_coefficient;
            } else if (idx == s.threshold) {
                contrib = lagr * (s.geq_coefficient + s.eq_coefficient);
            }
            switch (c) {
            case 0: t00 += contrib; break;
            case 1: t01 += contrib; break;
            case 2: t10 += contrib; break;
            default: t11 += contrib; break;
            }
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    ext_t a00 = partialBlockReduce(block, tile, t00, shared);
    block.sync();
    ext_t a01 = partialBlockReduce(block, tile, t01, shared);
    block.sync();
    ext_t a10 = partialBlockReduce(block, tile, t10, shared);
    block.sync();
    ext_t a11 = partialBlockReduce(block, tile, t11, shared);

    if (threadIdx.x == 0) {
        const ext_t coeff = lambda * pad_adj;
        const ext_t ax = a10 - a00;
        const ext_t ay = a01 - a00;
        const ext_t axy = (a11 - a10) - ay;
        const uint32_t base = out_idx * (uint32_t)BIVARIATE_NUM_NODES;
        for (int e = 0; e < BIVARIATE_NUM_NODES; e++) {
            const BivariateNode nd = bivariate_node(e);
            ext_t S = a00 + mul_small_pow2(ax, nd.cx) + mul_small_pow2(ay, nd.cy)
                + mul_small_pow2(axy, nd.cxy);
            ext_t::store(partials, base + (uint32_t)e, ext_t::zero() - coeff * S);
        }
    }
}

}  // namespace

extern "C" void* zerocheck_fix_geq_state_kernel() {
    return (void*)zerocheck_fix_geq_state;
}

extern "C" void* zerocheck_geq_corrections_kernel() {
    return (void*)zerocheck_geq_corrections;
}

extern "C" void* zerocheck_geq_corrections_bivariate_kernel() {
    return (void*)zerocheck_geq_corrections_bivariate;
}
