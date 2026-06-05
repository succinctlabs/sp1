#include "config.cuh"
#include "product_sumcheck/product_sumcheck.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

// Degree-K product sumcheck round message kernel.
//
// Layout:
//   mles[j * inputHeight + i]   = A_j(i)         for j in [0, K), i in [0, 2^n)
//   result[e * gridDim.x + b]   = block-b partial sum for eval point e
//
// We compute p(t) at K eval points t in {0, 2, 3, ..., K} (the K+1th eval
// p(1) is recovered on the host via claim - p(0)).  Each block writes its
// per-eval partial sum; the host (or a follow-up reduce) sums across blocks.
template <typename F, int K>
__global__ void productSumcheckSumAsPoly(
    ext_t* __restrict__ result, const F* __restrict__ mles, size_t numVariablesMinusOne) {
    static_assert(K >= 2, "K must be at least 2");

    size_t outputHeight = ((size_t)1) << numVariablesMinusOne;
    size_t inputHeight = outputHeight << 1;

    // K running evaluation accumulators (over all i this thread visits).
    ext_t evals[K];
#pragma unroll
    for (int e = 0; e < K; ++e) {
        evals[e] = ext_t::zero();
    }

    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {
        size_t evenIdx = i << 1;
        size_t oddIdx = evenIdx + 1;

        // Compute the K factor values at t = 0, 2, 3, ..., K for the j = 0 multilinear.
        //
        // Each factor at t = k is a_lo + k * d where d = a_hi - a_lo.  We build them with one
        // addition per step (cur += d) instead of a multiplication by k, skipping the unused
        // t = 1 value (which is recovered on the host from the round claim).
        F a_lo = F::load(mles, evenIdx);
        F a_hi = F::load(mles, oddIdx);
        F d = a_hi - a_lo;

        F prod[K];
        prod[0] = a_lo;       // factor at t = 0
        F cur = a_lo + d;     // = a_lo + 1*d (factor at t = 1, skipped)
#pragma unroll
        for (int e = 1; e < K; ++e) {
            cur = cur + d;    // cur = a_lo + (e + 1) * d ⇒ factor at t = e + 1
            prod[e] = cur;
        }

        // Stream over the remaining K-1 multilinears, multiplying factors in.
#pragma unroll
        for (int j = 1; j < K; ++j) {
            F a_lo_j = F::load(mles, j * inputHeight + evenIdx);
            F a_hi_j = F::load(mles, j * inputHeight + oddIdx);
            F d_j = a_hi_j - a_lo_j;

            prod[0] = prod[0] * a_lo_j;
            F cur_j = a_lo_j + d_j;
#pragma unroll
            for (int e = 1; e < K; ++e) {
                cur_j = cur_j + d_j;
                prod[e] = prod[e] * cur_j;
            }
        }

        // Lift base products into ext_t and accumulate.
#pragma unroll
        for (int e = 0; e < K; ++e) {
            evals[e] += ext_t(prod[e]);
        }
    }

    // Per-block reduction across threads, one eval point at a time.
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

#pragma unroll
    for (int e = 0; e < K; ++e) {
        ext_t blockSum = partialBlockReduce(block, tile, evals[e], shared);
        if (threadIdx.x == 0) {
            ext_t::store(result, e * gridDim.x + blockIdx.x, blockSum);
        }
        block.sync();  // shared mem is reused for the next eval point
    }
}

// kb31_extension_t::operator= is missing for ext_t = kb31_t in the headers we depend on, so we
// rely on the implicit constructor ext_t(kb31_t).  For F = ext_t the `ext_t(prod[e])` invocation
// becomes the copy constructor.

// Fused fold-and-sum kernel.
//
// In one pass over the input (size N before this fold), each thread:
//   * Reads 4 input values per multilinear (the lo/hi pair for output index 2*x_top and the
//     lo/hi pair for output index 2*x_top + 1).
//   * Folds the last variable by alpha → 2 ext_t output values per multilinear.
//   * Writes the 2K folded values to the output buffer (size N/2, the input for the next round's
//     fold).
//   * Treats those 2 freshly-folded values per multilinear as (v_lo, v_hi) for the NEXT round's
//     sum-as-poly over x_top, computing K eval-point partial products and accumulating into
//     this thread's per-eval-point sums.
//
// Layouts:
//   input          : [K, inputHeight]
//   output         : [K, outputHeight = inputHeight / 2]
//   univariate_out : [K, gridDim.x]
template <typename F, int K>
__global__ void productSumcheckFixAndSumAsPoly(
    const F* __restrict__ input,
    ext_t* __restrict__ output,
    ext_t alpha,
    ext_t* __restrict__ univariate_result,
    size_t inputHeight) {
    static_assert(K >= 2, "K must be at least 2");

    size_t outputHeight = inputHeight >> 1;
    // x_top ranges over the NEXT round's hypercube (half of the post-fold MLE).
    size_t numXTop = outputHeight >> 1;

    ext_t evals[K];
#pragma unroll
    for (int e = 0; e < K; ++e) {
        evals[e] = ext_t::zero();
    }

    for (size_t x_top = blockDim.x * blockIdx.x + threadIdx.x; x_top < numXTop;
         x_top += blockDim.x * gridDim.x) {
        size_t i_lo_out = x_top << 1;
        size_t i_hi_out = i_lo_out + 1;
        size_t base_in = x_top << 2;

        // Running products at eval points t = 0, 2, 3, ..., K.  Built incrementally:
        // factor(0) = v_lo, then cur = v_lo + d skips t = 1, and each subsequent step
        // adds d to advance to the next eval point.
        ext_t prod[K];

        // j = 0: initialize.
        {
            F a0 = F::load(input, base_in);
            F a1 = F::load(input, base_in + 1);
            F a2 = F::load(input, base_in + 2);
            F a3 = F::load(input, base_in + 3);

            ext_t v_lo = alpha.interpolateLinear(a1, a0);
            ext_t v_hi = alpha.interpolateLinear(a3, a2);

            ext_t::store(output, i_lo_out, v_lo);
            ext_t::store(output, i_hi_out, v_hi);

            prod[0] = v_lo;
            ext_t d = v_hi - v_lo;
            ext_t cur = v_lo + d;  // skipped factor at t = 1
#pragma unroll
            for (int e = 1; e < K; ++e) {
                cur = cur + d;
                prod[e] = cur;
            }
        }

        // j = 1..K-1: stream.
#pragma unroll
        for (int j = 1; j < K; ++j) {
            F a0 = F::load(input, j * inputHeight + base_in);
            F a1 = F::load(input, j * inputHeight + base_in + 1);
            F a2 = F::load(input, j * inputHeight + base_in + 2);
            F a3 = F::load(input, j * inputHeight + base_in + 3);

            ext_t v_lo = alpha.interpolateLinear(a1, a0);
            ext_t v_hi = alpha.interpolateLinear(a3, a2);

            ext_t::store(output, j * outputHeight + i_lo_out, v_lo);
            ext_t::store(output, j * outputHeight + i_hi_out, v_hi);

            prod[0] = prod[0] * v_lo;
            ext_t d = v_hi - v_lo;
            ext_t cur = v_lo + d;
#pragma unroll
            for (int e = 1; e < K; ++e) {
                cur = cur + d;
                prod[e] = prod[e] * cur;
            }
        }

#pragma unroll
        for (int e = 0; e < K; ++e) {
            evals[e] += prod[e];
        }
    }

    // Per-block reduction across threads, one eval point at a time.
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

#pragma unroll
    for (int e = 0; e < K; ++e) {
        ext_t blockSum = partialBlockReduce(block, tile, evals[e], shared);
        if (threadIdx.x == 0) {
            ext_t::store(univariate_result, e * gridDim.x + blockIdx.x, blockSum);
        }
        block.sync();
    }
}

// Round 0 always operates on base-field input — only the felt_t instantiations are live.
extern "C" void* product_sumcheck_sum_as_poly_base_2_kernel() {
    return (void*)productSumcheckSumAsPoly<felt_t, 2>;
}
extern "C" void* product_sumcheck_sum_as_poly_base_4_kernel() {
    return (void*)productSumcheckSumAsPoly<felt_t, 4>;
}
extern "C" void* product_sumcheck_sum_as_poly_base_8_kernel() {
    return (void*)productSumcheckSumAsPoly<felt_t, 8>;
}
extern "C" void* product_sumcheck_sum_as_poly_base_16_kernel() {
    return (void*)productSumcheckSumAsPoly<felt_t, 16>;
}
extern "C" void* product_sumcheck_sum_as_poly_base_32_kernel() {
    return (void*)productSumcheckSumAsPoly<felt_t, 32>;
}
extern "C" void* product_sumcheck_sum_as_poly_base_64_kernel() {
    return (void*)productSumcheckSumAsPoly<felt_t, 64>;
}

// Simple (thread-per-x_top) fused kernel is used only for small K, where register pressure
// is fine.  For K >= 16 we use the cooperative variant.
extern "C" void* product_sumcheck_fix_and_sum_base_2_kernel() {
    return (void*)productSumcheckFixAndSumAsPoly<felt_t, 2>;
}
extern "C" void* product_sumcheck_fix_and_sum_base_4_kernel() {
    return (void*)productSumcheckFixAndSumAsPoly<felt_t, 4>;
}
extern "C" void* product_sumcheck_fix_and_sum_base_8_kernel() {
    return (void*)productSumcheckFixAndSumAsPoly<felt_t, 8>;
}

extern "C" void* product_sumcheck_fix_and_sum_ext_2_kernel() {
    return (void*)productSumcheckFixAndSumAsPoly<ext_t, 2>;
}
extern "C" void* product_sumcheck_fix_and_sum_ext_4_kernel() {
    return (void*)productSumcheckFixAndSumAsPoly<ext_t, 4>;
}
extern "C" void* product_sumcheck_fix_and_sum_ext_8_kernel() {
    return (void*)productSumcheckFixAndSumAsPoly<ext_t, 8>;
}

// =====================================================================================
// Cooperative variant of the fused fix-and-sum kernel.
//
// The thread-per-x_top design hits a register cliff at large K (≥ 32): each thread has
// to hold K running products plus K eval-point accumulators, and the kernel spills heavily
// to local memory.  Occupancy at K = 64 collapses to ~1/6 of the SM.
//
// Here we instead use K threads cooperatively per x_top, each thread owning ONE eval
// point.  We pack TILES_PER_BLOCK = BLOCK_SIZE / K independent x_top tiles into one block.
// Per-thread register footprint drops from O(K) to O(1) ext elements, restoring full
// occupancy.
//
// Per (tile, x_top):
//   1. Thread `eval_idx` reads MLE j = eval_idx, folds, writes 2 output values to global
//      memory AND stashes (v_lo, v_hi) in shared.  __syncthreads.
//   2. Each thread reads all K (v_lo, v_hi) pairs from shared and computes the running
//      product for its assigned eval point t.  Each thread accumulates into its single
//      eval_acc register.  __syncthreads.
//
// After the outer loop, we tree-reduce eval_acc across the TPB tiles (for matching eval
// points) and write per-block partial sums to univariate_result.
template <typename F, int K>
__global__ void productSumcheckFixAndSumAsPolyCoop(
    const F* __restrict__ input,
    ext_t* __restrict__ output,
    ext_t alpha,
    ext_t* __restrict__ univariate_result,
    size_t inputHeight) {
    static_assert(K >= 2, "K must be at least 2");
    constexpr int BLOCK_SIZE = 256;
    constexpr int TILES_PER_BLOCK = BLOCK_SIZE / K;
    static_assert(TILES_PER_BLOCK >= 1, "BLOCK_SIZE must be >= K");
    static_assert(TILES_PER_BLOCK * K == BLOCK_SIZE, "K must divide BLOCK_SIZE");

    int tile_id = threadIdx.x / K;
    int eval_idx = threadIdx.x % K;

    // t value this thread owns: eval_idx=0 → t=0; eval_idx>=1 → t=eval_idx+1.
    // For eval_idx=0 we let my_t_kb=0; the formula v_lo + 0·d collapses to v_lo cleanly,
    // saving us a branch in the inner loop (at the cost of K-1 trivial muls-by-zero in
    // the t=0 thread, which is negligible).
    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    size_t outputHeight = inputHeight >> 1;
    size_t numXTop = outputHeight >> 1;

    // Two-purpose shared buffer: holds (v_lo, v_hi) pairs during the main loop, then
    // per-tile eval_acc values during the final reduction.  Sized for the larger of the
    // two layouts (the v-buffer at 2·K per tile).
    __shared__ ext_t shared_buf[TILES_PER_BLOCK * 2 * K];

    ext_t eval_acc = ext_t::zero();

    // Block-uniform iteration count.  Per CUDA semantics __syncthreads must be hit by every
    // thread in the block, so we cannot let some tiles fall out of the loop early when their
    // x_top is past numXTop — they have to keep showing up at the barriers.  Compute the
    // number of iterations any tile in this block needs, then gate the actual work on
    // `active` inside.
    size_t x_top_step = (size_t)gridDim.x * TILES_PER_BLOCK;
    size_t block_start = (size_t)blockIdx.x * TILES_PER_BLOCK;
    size_t block_iter_count =
        (block_start >= numXTop) ? 0 : ((numXTop - 1 - block_start) / x_top_step + 1);

    for (size_t iter = 0; iter < block_iter_count; ++iter) {
        size_t x_top = block_start + tile_id + iter * x_top_step;
        bool active = x_top < numXTop;

        if (active) {
            size_t base_in = x_top << 2;
            size_t i_lo_out = x_top << 1;
            size_t i_hi_out = i_lo_out + 1;

            int j = eval_idx;
            F a0 = F::load(input, j * inputHeight + base_in);
            F a1 = F::load(input, j * inputHeight + base_in + 1);
            F a2 = F::load(input, j * inputHeight + base_in + 2);
            F a3 = F::load(input, j * inputHeight + base_in + 3);

            ext_t v_lo_j = alpha.interpolateLinear(a1, a0);
            ext_t v_hi_j = alpha.interpolateLinear(a3, a2);

            ext_t::store(output, j * outputHeight + i_lo_out, v_lo_j);
            ext_t::store(output, j * outputHeight + i_hi_out, v_hi_j);

            size_t shared_tile_base = (size_t)tile_id * 2 * K;
            ext_t::store(shared_buf, shared_tile_base + 2 * j + 0, v_lo_j);
            ext_t::store(shared_buf, shared_tile_base + 2 * j + 1, v_hi_j);
        }

        __syncthreads();

        if (active) {
            // Compute prod_j (v_lo_j + my_t · (v_hi_j - v_lo_j)) over all K multilinears.
            size_t shared_tile_base = (size_t)tile_id * 2 * K;
            ext_t prod;
            {
                ext_t v_lo_0 = ext_t::load(shared_buf, shared_tile_base + 0);
                ext_t v_hi_0 = ext_t::load(shared_buf, shared_tile_base + 1);
                ext_t d_0 = v_hi_0 - v_lo_0;
                prod = v_lo_0 + d_0 * my_t_kb;
            }
#pragma unroll
            for (int jj = 1; jj < K; ++jj) {
                ext_t v_lo = ext_t::load(shared_buf, shared_tile_base + 2 * jj);
                ext_t v_hi = ext_t::load(shared_buf, shared_tile_base + 2 * jj + 1);
                ext_t d = v_hi - v_lo;
                ext_t factor = v_lo + d * my_t_kb;
                prod = prod * factor;
            }
            eval_acc += prod;
        }

        __syncthreads();  // sync before next iteration reuses shared_buf
    }

    // Reuse shared_buf as `shared_evals[eval_idx][tile_id]` to reduce across tiles.
    // Layout: shared_buf[eval_idx * TILES_PER_BLOCK + tile_id].
    // This fits because TILES_PER_BLOCK * K = BLOCK_SIZE <= 2 * K * TILES_PER_BLOCK.
    ext_t::store(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id, eval_acc);
    __syncthreads();

#pragma unroll
    for (int stride = TILES_PER_BLOCK >> 1; stride > 0; stride >>= 1) {
        if (tile_id < stride) {
            ext_t a =
                ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id);
            ext_t b = ext_t::load(
                shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id + stride);
            ext_t::store(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id, a + b);
        }
        __syncthreads();
    }

    if (tile_id == 0) {
        ext_t block_sum = ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK);
        ext_t::store(univariate_result, (size_t)eval_idx * gridDim.x + blockIdx.x, block_sum);
    }
}

// Cooperative kernel is used only for large K (K >= 16), where the simple kernel spills.
extern "C" void* product_sumcheck_fix_and_sum_coop_base_16_kernel() {
    return (void*)productSumcheckFixAndSumAsPolyCoop<felt_t, 16>;
}
extern "C" void* product_sumcheck_fix_and_sum_coop_base_32_kernel() {
    return (void*)productSumcheckFixAndSumAsPolyCoop<felt_t, 32>;
}
extern "C" void* product_sumcheck_fix_and_sum_coop_base_64_kernel() {
    return (void*)productSumcheckFixAndSumAsPolyCoop<felt_t, 64>;
}

extern "C" void* product_sumcheck_fix_and_sum_coop_ext_16_kernel() {
    return (void*)productSumcheckFixAndSumAsPolyCoop<ext_t, 16>;
}
extern "C" void* product_sumcheck_fix_and_sum_coop_ext_32_kernel() {
    return (void*)productSumcheckFixAndSumAsPolyCoop<ext_t, 32>;
}
extern "C" void* product_sumcheck_fix_and_sum_coop_ext_64_kernel() {
    return (void*)productSumcheckFixAndSumAsPolyCoop<ext_t, 64>;
}
