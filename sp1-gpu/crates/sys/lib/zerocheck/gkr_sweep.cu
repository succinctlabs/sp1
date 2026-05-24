// Per-chip GKR column sweep — see gkr_sweep.cuh for the algorithm overview.
//
// Templated on K ∈ {felt_t, ext_t} so round 0 uses the base-field trace and
// rounds 1+ use the ext-field folded trace, matching the constraint kernel.

#include "zerocheck/gkr_sweep.cuh"
#include "zerocheck/sequential.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

// Per-row interp helper — `z + ep_v * (o - z)` rewritten with the standard
// diff-doubling trick (see sequential.cu banner). `e` is uniform across the
// block.
template <typename K>
__device__ __forceinline__ K interp_load(
    const K* trace_data, size_t base, uint32_t col, uint32_t height,
    uint32_t row_idx, int e)
{
    K z = K::load(trace_data, base + col * height + (row_idx << 1));
    if (e == 0) {
        return z;
    }
    K o = K::load(trace_data, base + col * height + (row_idx << 1 | 1));
    K diff = o - z;
    K d2 = diff + diff;
    return (e == 1) ? (z + d2) : (z + d2 + d2);
}

template <typename K>
__global__ void zerocheck_gkr_sweep(
    const BlockDispatch* __restrict__ dispatch,
    const ChipLayout* __restrict__ chip_layouts,
    const ChipGkrInfo* __restrict__ chip_gkr,
    const K* __restrict__ trace_data,
    const ext_t* __restrict__ gkr_powers,
    const ext_t* __restrict__ partial_lagrange,
    const ext_t* __restrict__ powers_of_lambda,
    uint32_t rest_point_dim,
    ext_t* __restrict__ partials
) {
    // Per-block uniform setup. `chunk_id` overloads as chip_idx.
    BlockDispatch disp = dispatch[blockIdx.x];
    uint32_t chip_idx = disp.chunk_id;
    ChipLayout lay = chip_layouts[chip_idx];
    ChipGkrInfo gkr = chip_gkr[chip_idx];

    const int e = blockIdx.z;
    const uint32_t row_limit = 1u << rest_point_dim;
    const uint32_t row_end = disp.row_offset + disp.n_rows;
    const ext_t lambda = ext_t::load(powers_of_lambda, chip_idx);

    constexpr int WARP_SIZE = 32;
    constexpr int WARPS_PER_BLOCK = GKR_SWEEP_BLOCK_SIZE / WARP_SIZE;
    auto block = cg::this_thread_block();

    // Per-block uniform branch — every thread sees the same chip params,
    // so the branch costs nothing (no warp divergence).
    //
    // Narrow path (total_width <= WARP_SIZE): thread-per-row, columns in
    // a tight inner loop. Matches the old carrier-chunk inline cost
    // profile so workloads dominated by narrow chips don't regress.
    //
    // Wide path (total_width > WARP_SIZE): warp-per-row with lane-strided
    // column reduction. Scales to chips with widths in the thousands
    // because the per-row column work parallelises across the warp.
    const uint32_t total_width = gkr.main_width + gkr.prep_width;
    ext_t thread_acc = ext_t::zero();
    if (total_width <= (uint32_t)WARP_SIZE) {
        // ---- Narrow path: thread-per-row, columns in inner loop ----
        for (uint32_t row_idx = disp.row_offset + threadIdx.x;
             row_idx < row_end;
             row_idx += blockDim.x)
        {
            ext_t acc = ext_t::zero();
            for (uint32_t i = 0; i < gkr.main_width; i++) {
                K v = interp_load(trace_data, lay.main_ptr, i, lay.height, row_idx, e);
                acc += ext_t::load(gkr_powers, i) * v;
            }
            for (uint32_t i = 0; i < gkr.prep_width; i++) {
                K v = interp_load(trace_data, lay.preprocessed_ptr, i, lay.height, row_idx, e);
                acc += ext_t::load(gkr_powers, gkr.main_width + i) * v;
            }
            if (row_idx < row_limit) {
                ext_t eq = ext_t::load(partial_lagrange, row_idx);
                thread_acc += acc * (eq * lambda);
            }
        }
    } else {
        // ---- Wide path: warp-per-row, lane-strided columns ----
        const int warp_id = threadIdx.x / WARP_SIZE;
        const int lane = threadIdx.x % WARP_SIZE;
        auto warp = cg::tiled_partition<WARP_SIZE>(block);
        for (uint32_t row_idx = disp.row_offset + warp_id; row_idx < row_end;
             row_idx += WARPS_PER_BLOCK)
        {
            ext_t lane_sum = ext_t::zero();
            for (uint32_t col = (uint32_t)lane; col < gkr.main_width; col += WARP_SIZE) {
                K v = interp_load(trace_data, lay.main_ptr, col, lay.height, row_idx, e);
                lane_sum += ext_t::load(gkr_powers, col) * v;
            }
            for (uint32_t col = (uint32_t)lane; col < gkr.prep_width; col += WARP_SIZE) {
                K v = interp_load(trace_data, lay.preprocessed_ptr, col, lay.height, row_idx, e);
                lane_sum += ext_t::load(gkr_powers, gkr.main_width + col) * v;
            }
            ext_t row_total = cg::reduce(warp, lane_sum, cg::plus<ext_t>());
            if (lane == 0 && row_idx < row_limit) {
                ext_t eq = ext_t::load(partial_lagrange, row_idx);
                thread_acc += row_total * (eq * lambda);
            }
        }
    }

    // Block-reduce. Both paths leave non-trivial values in some threads and
    // zero in the rest, so the standard reduce just works.
    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);
    auto tile_warp = cg::tiled_partition<32>(block);
    ext_t block_sum = partialBlockReduce(block, tile_warp, thread_acc, shared);
    if (threadIdx.x == 0) {
        ext_t::store(partials, blockIdx.x * 3 + (uint32_t)e, block_sum);
    }
}

}  // namespace

extern "C" void* zerocheck_gkr_sweep_kb_kernel() {
    return (void*)zerocheck_gkr_sweep<felt_t>;
}
extern "C" void* zerocheck_gkr_sweep_ext_kernel() {
    return (void*)zerocheck_gkr_sweep<ext_t>;
}
