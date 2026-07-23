// Per-chip GKR column sweep — see gkr_sweep.cuh for the algorithm overview.
//
// Templated on K ∈ {felt_t, ext_t} so round 0 uses the base-field trace and
// rounds 1+ use the ext-field folded trace, matching the constraint kernel.

#include "zerocheck/gkr_sweep.cuh"
#include "zerocheck/bivariate.cuh"
#include "zerocheck/sequential.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

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
                K v = interp_load_pair(trace_data, lay.main_ptr, i, lay.height, row_idx, e);
                acc += ext_t::load(gkr_powers, i) * v;
            }
            for (uint32_t i = 0; i < gkr.prep_width; i++) {
                K v = interp_load_pair(trace_data, lay.preprocessed_ptr, i, lay.height, row_idx, e);
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
                K v = interp_load_pair(trace_data, lay.main_ptr, col, lay.height, row_idx, e);
                lane_sum += ext_t::load(gkr_powers, col) * v;
            }
            for (uint32_t col = (uint32_t)lane; col < gkr.prep_width; col += WARP_SIZE) {
                K v = interp_load_pair(
                    trace_data, lay.preprocessed_ptr, col, lay.height, row_idx, e);
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

// ============================================================================
// Corner sweep — the GKR opening batch for the fused first-two-rounds.
//
// The bivariate round polynomial's four boolean grid corners `(X, Y) ∈
// {0, 1}^2` need only the GKR opening batch (constraints vanish there); the
// corner value of row-quadruple `q` at corner `c = 2X + Y` is simply the raw
// trace row `4q + c` — no interpolation. Each block computes ALL four corner
// sums in one pass: per (quad, column), the four consecutive elements are
// loaded once (one cache line) and accumulated into their per-corner sums.
// Guarded against the column height: the last quadruple of a chip may have
// only two physical rows, and the missing rows are zero (which contribute
// zero to the sweep anyway, but an unguarded load would read the next
// column's data).
//
// One block per (chip, quad-tile); grid is (n_blocks, 1, 1); output stride 4.
// Runs for EVERY chip with non-zero width in the fused round — the inline
// carrier-chunk sweep is disabled there.
// ============================================================================

// Accumulate `gkr_power · element` into the four per-corner sums for one
// (quad, column) pair. The guard only fires on the chip's last quadruple.
template <typename K>
__device__ __forceinline__ void corner_accumulate(
    const K* trace_data, size_t base, uint32_t col, uint32_t height,
    uint32_t quad_idx, ext_t power, ext_t acc[BIVARIATE_NUM_CORNERS])
{
    const size_t col_off = (size_t)col * (size_t)height;
    const size_t quad_base = base + col_off + ((size_t)quad_idx << 2);
    const uint32_t elem0 = quad_idx << 2;
#pragma unroll
    for (int c = 0; c < BIVARIATE_NUM_CORNERS; c++) {
        if ((elem0 | (uint32_t)c) < height) {
            acc[c] += power * K::load(trace_data, quad_base + c);
        }
    }
}

template <typename K>
__global__ void zerocheck_gkr_corner_sweep(
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
    BlockDispatch disp = dispatch[blockIdx.x];
    uint32_t chip_idx = disp.chunk_id;
    ChipLayout lay = chip_layouts[chip_idx];
    ChipGkrInfo gkr = chip_gkr[chip_idx];

    const uint32_t quad_limit = 1u << rest_point_dim;
    const uint32_t quad_end = disp.row_offset + disp.n_rows;
    const ext_t lambda = ext_t::load(powers_of_lambda, chip_idx);

    constexpr int WARP_SIZE = 32;
    constexpr int WARPS_PER_BLOCK = GKR_SWEEP_BLOCK_SIZE / WARP_SIZE;
    auto block = cg::this_thread_block();

    const uint32_t total_width = gkr.main_width + gkr.prep_width;
    ext_t thread_acc[BIVARIATE_NUM_CORNERS] = {
        ext_t::zero(), ext_t::zero(), ext_t::zero(), ext_t::zero()};
    if (total_width <= (uint32_t)WARP_SIZE) {
        // ---- Narrow path: thread-per-quad, columns in inner loop ----
        for (uint32_t quad_idx = disp.row_offset + threadIdx.x;
             quad_idx < quad_end;
             quad_idx += blockDim.x)
        {
            if (quad_idx >= quad_limit) {
                continue;
            }
            ext_t acc[BIVARIATE_NUM_CORNERS] = {
                ext_t::zero(), ext_t::zero(), ext_t::zero(), ext_t::zero()};
            for (uint32_t i = 0; i < gkr.main_width; i++) {
                ext_t power = ext_t::load(gkr_powers, i);
                corner_accumulate(trace_data, lay.main_ptr, i, lay.height, quad_idx, power, acc);
            }
            for (uint32_t i = 0; i < gkr.prep_width; i++) {
                ext_t power = ext_t::load(gkr_powers, gkr.main_width + i);
                corner_accumulate(
                    trace_data, lay.preprocessed_ptr, i, lay.height, quad_idx, power, acc);
            }
            const ext_t w = ext_t::load(partial_lagrange, quad_idx) * lambda;
#pragma unroll
            for (int c = 0; c < BIVARIATE_NUM_CORNERS; c++) {
                thread_acc[c] += acc[c] * w;
            }
        }
    } else {
        // ---- Wide path: warp-per-quad, lane-strided columns ----
        const int warp_id = threadIdx.x / WARP_SIZE;
        const int lane = threadIdx.x % WARP_SIZE;
        auto warp = cg::tiled_partition<WARP_SIZE>(block);
        for (uint32_t quad_idx = disp.row_offset + warp_id; quad_idx < quad_end;
             quad_idx += WARPS_PER_BLOCK)
        {
            if (quad_idx >= quad_limit) {
                continue;
            }
            ext_t lane_sum[BIVARIATE_NUM_CORNERS] = {
                ext_t::zero(), ext_t::zero(), ext_t::zero(), ext_t::zero()};
            for (uint32_t col = (uint32_t)lane; col < gkr.main_width; col += WARP_SIZE) {
                ext_t power = ext_t::load(gkr_powers, col);
                corner_accumulate(
                    trace_data, lay.main_ptr, col, lay.height, quad_idx, power, lane_sum);
            }
            for (uint32_t col = (uint32_t)lane; col < gkr.prep_width; col += WARP_SIZE) {
                ext_t power = ext_t::load(gkr_powers, gkr.main_width + col);
                corner_accumulate(
                    trace_data, lay.preprocessed_ptr, col, lay.height, quad_idx, power, lane_sum);
            }
            const ext_t w = ext_t::load(partial_lagrange, quad_idx) * lambda;
#pragma unroll
            for (int c = 0; c < BIVARIATE_NUM_CORNERS; c++) {
                ext_t row_total = cg::reduce(warp, lane_sum[c], cg::plus<ext_t>());
                if (lane == 0) {
                    thread_acc[c] += row_total * w;
                }
            }
        }
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);
    auto tile_warp = cg::tiled_partition<32>(block);
    for (int c = 0; c < BIVARIATE_NUM_CORNERS; c++) {
        ext_t block_sum = partialBlockReduce(block, tile_warp, thread_acc[c], shared);
        if (threadIdx.x == 0) {
            ext_t::store(partials, blockIdx.x * BIVARIATE_NUM_CORNERS + (uint32_t)c, block_sum);
        }
        block.sync();
    }
}

}  // namespace

extern "C" void* zerocheck_gkr_sweep_kb_kernel() {
    return (void*)zerocheck_gkr_sweep<felt_t>;
}
extern "C" void* zerocheck_gkr_sweep_ext_kernel() {
    return (void*)zerocheck_gkr_sweep<ext_t>;
}
extern "C" void* zerocheck_gkr_corner_sweep_kb_kernel() {
    return (void*)zerocheck_gkr_corner_sweep<felt_t>;
}
