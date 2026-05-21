// v2 ColumnTile lowering.
//
// Each thread = one `(term, row)` pair. Per thread:
//   1. Look up term's coefficient (constant, public, or runtime ext_t).
//   2. Read `(zero, one)` for the term's leaf at this row (K-typed).
//   3. Compute interp at all 3 eval points (eval-point caching).
//   4. Multiply by `α^{term.alpha_idx} · coeff · eq[row] · λ_chip`.
//   5. Block-reduce per eval point into one partial per CTA per eval.
//
// Templated on `K` ∈ {felt_t, ext_t} for the trace element type. Constants
// and publics stay base-field; runtime coeffs and the per-row weighting
// stay extension-field; the accumulator is always ext_t.

#include "zerocheck/column_tile.cuh"
#include "zerocheck/sequential.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

__device__ __forceinline__ felt_t eval_point(int i) {
    return felt_t::from_canonical_u32(2u * i);
}

template <typename K>
__global__ void zerocheck_column_tile(
    const ColumnTermEntry* __restrict__ terms,
    uint32_t n_terms,
    const LeafRef* __restrict__ leaves,
    const felt_t* __restrict__ consts,
    const uint32_t* __restrict__ publics,
    const ext_t* __restrict__ runtime_coeffs,
    const K* __restrict__ trace_data,
    size_t preprocessed_ptr,
    size_t main_ptr,
    uint32_t height,
    const felt_t* __restrict__ public_values,
    const ext_t* __restrict__ powers_of_alpha,
    const ext_t* __restrict__ partial_lagrange,
    const ext_t* __restrict__ powers_of_lambda,
    uint32_t chip_idx,
    uint32_t rest_point_dim,
    uint32_t row_start,
    uint32_t row_count,
    ext_t* __restrict__ partials
) {
    const uint64_t total = (uint64_t)n_terms * (uint64_t)row_count;
    const uint64_t stride = (uint64_t)blockDim.x * (uint64_t)gridDim.x;
    const ext_t lambda = ext_t::load(powers_of_lambda, chip_idx);
    const uint32_t row_limit = 1u << rest_point_dim;

    ext_t thread_acc[3] = { ext_t::zero(), ext_t::zero(), ext_t::zero() };

    // Grid-stride loop. Each lane covers one (term, row) tuple per iter.
    for (uint64_t lane = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
         lane < total;
         lane += stride)
    {
        const uint32_t term_idx = (uint32_t)(lane / row_count);
        const uint32_t local_row = (uint32_t)(lane - (uint64_t)term_idx * row_count);
        const uint32_t row = row_start + local_row;

        ColumnTermEntry t = terms[term_idx];

        LeafRef leaf = leaves[t.leaf_idx];
        // source: 2 = preprocessed, 4 = main (local row only).
        size_t base = (leaf.source == 4) ? main_ptr : preprocessed_ptr;
        K z = K::load(trace_data, base + leaf.col * height + (row << 1));
        K o = K::load(trace_data, base + leaf.col * height + (row << 1 | 1));
        K diff = o - z;

        ext_t alpha = ext_t::load(powers_of_alpha, t.alpha_idx);

        K v0 = z;
        K v1 = z + eval_point(1) * diff;
        K v2 = z + eval_point(2) * diff;

        ext_t a0, a1, a2;
        if (t.coeff_kind == COEFF_KIND_RUNTIME) {
            ext_t coeff = ext_t::load(runtime_coeffs, t.coeff_idx);
            a0 = alpha * (coeff * v0);
            a1 = alpha * (coeff * v1);
            a2 = alpha * (coeff * v2);
        } else {
            felt_t coeff;
            if (t.coeff_kind == COEFF_KIND_CONST) {
                coeff = consts[t.coeff_idx];
            } else {
                uint32_t pv_idx = publics[t.coeff_idx];
                coeff = felt_t::load(public_values, pv_idx);
            }
            a0 = alpha * (coeff * v0);
            a1 = alpha * (coeff * v1);
            a2 = alpha * (coeff * v2);
        }

        if (row < row_limit) {
            ext_t eq = ext_t::load(partial_lagrange, row);
            ext_t w = eq * lambda;
            thread_acc[0] += a0 * w;
            thread_acc[1] += a1 * w;
            thread_acc[2] += a2 * w;
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);

    auto block = cg::this_thread_block();
    auto tile_warp = cg::tiled_partition<32>(block);

    for (int e = 0; e < 3; e++) {
        ext_t block_sum = partialBlockReduce(block, tile_warp, thread_acc[e], shared);
        if (threadIdx.x == 0) {
            ext_t::store(partials, blockIdx.x * 3 + e, block_sum);
        }
        __syncthreads();
    }
}

}  // namespace

extern "C" void* zerocheck_column_tile_kb_kernel() {
    return (void*)zerocheck_column_tile<felt_t>;
}

extern "C" void* zerocheck_column_tile_ext_kernel() {
    return (void*)zerocheck_column_tile<ext_t>;
}
