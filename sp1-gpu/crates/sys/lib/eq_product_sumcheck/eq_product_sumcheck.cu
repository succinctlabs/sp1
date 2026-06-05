#include "config.cuh"
#include "eq_product_sumcheck/eq_product_sumcheck.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

// Eq-prefixed degree-(K+1) product sumcheck (K = 64).
//
// Per round we evaluate h_r(t) at K kernel points t ∈ {0, 2, 3, ..., K}:
//   h_r(t) = ∑_{x ∈ {0,1}^{n-r}} E_r(x) · ∏_{j=0..K} eq(z_j, p_j(x, t))
//          = ∑_x E_r(x) · ∏_j (u_j(x) + t · v_j(x))
// where u_j(x) = a_j + b_j · p_j(x, 0) and v_j(x) = b_j · (p_j(x, 1) - p_j(x, 0)),
// with precomputed a_j = 1 − z_j and b_j = 2 z_j − 1.
//
// Cooperative layout: K threads per tile, TILES_PER_BLOCK = 256 / K = 4 tiles per block.
// Each thread (tile_id, eval_idx):
//   * Loads the j = eval_idx MLE pair for its x.
//   * Computes u_j, v_j.  Thread eval_idx = 0 also absorbs E_r(x) into (u_0, v_0) — this
//     scales the running product through the j = 0 factor for free, saving K - 1 ext × ext
//     mults per x (vs scaling each of K running products separately).
//   * Stashes (u_j, v_j) in shared.
//   * After __syncthreads, reads all K (u_jj, v_jj) pairs and computes its assigned
//     eval-point running product ∏_jj (u_jj + my_t · v_jj).
//   * Accumulates into its own eval_acc across x.
// At block end, tile-wise tree-reduce eval_acc across same-eval_idx threads, write one
// per-block partial sum per eval point.

namespace {
constexpr int K = 64;
constexpr int BLOCK_SIZE = 256;
constexpr int TILES_PER_BLOCK = BLOCK_SIZE / K; // 4
static_assert(TILES_PER_BLOCK * K == BLOCK_SIZE, "K must divide BLOCK_SIZE");
} // namespace

template <typename F>
__global__ void eqProductSumAsPolyCoop(
    ext_t* __restrict__ result,
    const F* __restrict__ mles,
    const ext_t* __restrict__ eq_prefix,
    const ext_t* __restrict__ a,
    const ext_t* __restrict__ b,
    size_t numXTop) {
    int tile_id = threadIdx.x / K;
    int eval_idx = threadIdx.x % K;

    // Eval point this thread owns: eval_idx = 0 → t = 0; eval_idx >= 1 → t = eval_idx + 1.
    // For eval_idx = 0 we let my_t_kb = 0 so factor(0) = u_0 collapses cleanly.
    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    // Dual-purpose shared buffer: holds (u_j, v_j) pairs during the main loop, then the
    // per-eval per-tile accumulators during the final tree reduce.
    __shared__ ext_t shared_buf[TILES_PER_BLOCK * 2 * K];

    ext_t eval_acc = ext_t::zero();

    // Block-uniform iteration: every thread enters the loop the same number of times and
    // reaches every __syncthreads, even if numXTop < TILES_PER_BLOCK in late rounds.
    size_t x_top_step = (size_t)gridDim.x * TILES_PER_BLOCK;
    size_t block_start = (size_t)blockIdx.x * TILES_PER_BLOCK;
    size_t block_iter_count =
        (block_start >= numXTop) ? 0 : ((numXTop - 1 - block_start) / x_top_step + 1);

    for (size_t iter = 0; iter < block_iter_count; ++iter) {
        size_t x = block_start + tile_id + iter * x_top_step;
        bool active = x < numXTop;

        if (active) {
            int j = eval_idx;
            size_t inputHeight = numXTop << 1;
            size_t lo_idx = x << 1;
            size_t hi_idx = lo_idx + 1;
            F p_lo = F::load(mles, j * inputHeight + lo_idx);
            F p_hi = F::load(mles, j * inputHeight + hi_idx);

            ext_t a_j = ext_t::load(a, j);
            ext_t b_j = ext_t::load(b, j);
            F d = p_hi - p_lo;
            ext_t u_j = a_j + b_j * p_lo; // ext + ext × F → ext
            ext_t v_j = b_j * d;          // ext × F → ext

            // Absorb the eq prefix into u_0 and v_0 once per x — propagates the eq scaling
            // through all K running products via the j = 0 factor.
            if (eval_idx == 0) {
                ext_t eq_val = ext_t::load(eq_prefix, x);
                u_j = eq_val * u_j;
                v_j = eq_val * v_j;
            }

            size_t shared_tile_base = (size_t)tile_id * 2 * K;
            ext_t::store(shared_buf, shared_tile_base + 2 * j + 0, u_j);
            ext_t::store(shared_buf, shared_tile_base + 2 * j + 1, v_j);
        }

        __syncthreads();

        if (active) {
            size_t shared_tile_base = (size_t)tile_id * 2 * K;
            ext_t prod;
            {
                ext_t u0 = ext_t::load(shared_buf, shared_tile_base + 0);
                ext_t v0 = ext_t::load(shared_buf, shared_tile_base + 1);
                prod = u0 + v0 * my_t_kb;
            }
#pragma unroll
            for (int jj = 1; jj < K; ++jj) {
                ext_t u = ext_t::load(shared_buf, shared_tile_base + 2 * jj);
                ext_t v = ext_t::load(shared_buf, shared_tile_base + 2 * jj + 1);
                ext_t factor = u + v * my_t_kb;
                prod = prod * factor;
            }
            eval_acc += prod;
        }

        __syncthreads(); // before reusing shared_buf
    }

    // Reuse shared_buf as `shared_evals[eval_idx][tile_id]` to reduce across tiles.
    ext_t::store(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id, eval_acc);
    __syncthreads();

#pragma unroll
    for (int stride = TILES_PER_BLOCK >> 1; stride > 0; stride >>= 1) {
        if (tile_id < stride) {
            ext_t a_v = ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id);
            ext_t b_v =
                ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id + stride);
            ext_t::store(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id, a_v + b_v);
        }
        __syncthreads();
    }

    if (tile_id == 0) {
        ext_t block_sum = ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK);
        ext_t::store(result, (size_t)eval_idx * gridDim.x + blockIdx.x, block_sum);
    }
}

// Fused fold-by-alpha + sum-as-poly for the eq-prefixed sumcheck.
//
// Combines (a) folding the K-batched MLE by the just-sampled alpha, (b) the eq-prefix
// transition new_eq[x_top] = scalar · (old_eq[2 x_top] + old_eq[2 x_top + 1]) — where
// `scalar = eq(ζ_{r−1}, α_{r−1})` is computed on the host — and (c) the cooperative
// sum-as-poly for the NEXT round, into one pass over the input MLE.  Avoids reloading the
// folded MLE for the next round's sum_as_poly.
//
// Each thread handles ONE x_top of the next round's hypercube:
//   * Reads 4 input MLE values for j = eval_idx (positions 4·x_top..4·x_top+3 in the
//     j-th column), folds adjacent pairs by alpha to v_lo (= folded value at 2·x_top) and
//     v_hi (= folded value at 2·x_top+1).
//   * Writes the two folded values to output_mles for the next round's fused step (or final
//     fold).
//   * Computes (u_j, v_j) = (a_j + b_j · v_lo, b_j · (v_hi − v_lo)).
//   * Thread eval_idx = 0 also reads two old-eq entries, sum-pairs + scales by `scalar`,
//     writes the new eq entry to output_eq, and absorbs new_eq into (u_0, v_0).
//   * Stashes (u_j, v_j) in shared; after __syncthreads, computes its assigned
//     eval-point running product over K factors and accumulates.
template <typename F>
__global__ void eqProductFixAndSumAsPolyCoop(
    const F* __restrict__ input_mles,
    ext_t* __restrict__ output_mles,
    const ext_t* __restrict__ input_eq,
    ext_t* __restrict__ output_eq,
    const ext_t* __restrict__ a,
    const ext_t* __restrict__ b,
    ext_t alpha,
    ext_t eq_scalar,
    ext_t* __restrict__ univariate_result,
    size_t inputHeight) {
    int tile_id = threadIdx.x / K;
    int eval_idx = threadIdx.x % K;

    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    size_t outputHeight = inputHeight >> 1;
    size_t numXTop = outputHeight >> 1; // = inputHeight / 4 = new eq prefix size

    __shared__ ext_t shared_buf[TILES_PER_BLOCK * 2 * K];

    ext_t eval_acc = ext_t::zero();

    size_t x_top_step = (size_t)gridDim.x * TILES_PER_BLOCK;
    size_t block_start = (size_t)blockIdx.x * TILES_PER_BLOCK;
    size_t block_iter_count =
        (block_start >= numXTop) ? 0 : ((numXTop - 1 - block_start) / x_top_step + 1);

    for (size_t iter = 0; iter < block_iter_count; ++iter) {
        size_t x_top = block_start + tile_id + iter * x_top_step;
        bool active = x_top < numXTop;

        if (active) {
            int j = eval_idx;
            size_t base_in = x_top << 2;
            size_t lo_out = x_top << 1;
            size_t hi_out = lo_out + 1;

            F a0 = F::load(input_mles, j * inputHeight + base_in);
            F a1 = F::load(input_mles, j * inputHeight + base_in + 1);
            F a2 = F::load(input_mles, j * inputHeight + base_in + 2);
            F a3 = F::load(input_mles, j * inputHeight + base_in + 3);

            ext_t v_lo = alpha.interpolateLinear(a1, a0);
            ext_t v_hi = alpha.interpolateLinear(a3, a2);

            ext_t::store(output_mles, j * outputHeight + lo_out, v_lo);
            ext_t::store(output_mles, j * outputHeight + hi_out, v_hi);

            ext_t a_j = ext_t::load(a, j);
            ext_t b_j = ext_t::load(b, j);
            ext_t d = v_hi - v_lo;
            ext_t u_j = a_j + b_j * v_lo;
            ext_t v_j = b_j * d;

            // Eval_idx = 0 also handles the eq prefix transition and the eq absorption.
            if (eval_idx == 0) {
                ext_t eq_lo = ext_t::load(input_eq, 2 * x_top);
                ext_t eq_hi = ext_t::load(input_eq, 2 * x_top + 1);
                ext_t new_eq = (eq_lo + eq_hi) * eq_scalar;
                ext_t::store(output_eq, x_top, new_eq);
                u_j = new_eq * u_j;
                v_j = new_eq * v_j;
            }

            size_t shared_tile_base = (size_t)tile_id * 2 * K;
            ext_t::store(shared_buf, shared_tile_base + 2 * j + 0, u_j);
            ext_t::store(shared_buf, shared_tile_base + 2 * j + 1, v_j);
        }

        __syncthreads();

        if (active) {
            size_t shared_tile_base = (size_t)tile_id * 2 * K;
            ext_t prod;
            {
                ext_t u0 = ext_t::load(shared_buf, shared_tile_base + 0);
                ext_t v0 = ext_t::load(shared_buf, shared_tile_base + 1);
                prod = u0 + v0 * my_t_kb;
            }
#pragma unroll
            for (int jj = 1; jj < K; ++jj) {
                ext_t u = ext_t::load(shared_buf, shared_tile_base + 2 * jj);
                ext_t v = ext_t::load(shared_buf, shared_tile_base + 2 * jj + 1);
                ext_t factor = u + v * my_t_kb;
                prod = prod * factor;
            }
            eval_acc += prod;
        }

        __syncthreads();
    }

    // Reduce eval_acc across tiles.
    ext_t::store(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id, eval_acc);
    __syncthreads();

#pragma unroll
    for (int stride = TILES_PER_BLOCK >> 1; stride > 0; stride >>= 1) {
        if (tile_id < stride) {
            ext_t a_v = ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id);
            ext_t b_v =
                ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id + stride);
            ext_t::store(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK + tile_id, a_v + b_v);
        }
        __syncthreads();
    }

    if (tile_id == 0) {
        ext_t block_sum = ext_t::load(shared_buf, (size_t)eval_idx * TILES_PER_BLOCK);
        ext_t::store(univariate_result, (size_t)eval_idx * gridDim.x + blockIdx.x, block_sum);
    }
}

// Eq prefix transition: new_eq[i] = scalar * (old_eq[2*i] + old_eq[2*i+1]).
//
// The pair-sum drops the just-folded variable's eq factor from the prefix (since
// eq(ζ_r, 0) + eq(ζ_r, 1) = 1).  The scalar = eq(ζ_r, α_r) is absorbed here so the next
// round's prover message naturally includes the cumulative C_r factor.
__global__ void eqPrefixFold(
    ext_t* __restrict__ new_eq,
    const ext_t* __restrict__ old_eq,
    ext_t scalar,
    size_t new_size) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < new_size;
         i += blockDim.x * gridDim.x) {
        ext_t lo = ext_t::load(old_eq, 2 * i);
        ext_t hi = ext_t::load(old_eq, 2 * i + 1);
        ext_t sum = lo + hi;
        ext_t res = sum * scalar;
        ext_t::store(new_eq, i, res);
    }
}

extern "C" void* eq_product_sum_as_poly_base_64_coop_kernel() {
    return (void*)eqProductSumAsPolyCoop<felt_t>;
}

extern "C" void* eq_product_sum_as_poly_ext_64_coop_kernel() {
    return (void*)eqProductSumAsPolyCoop<ext_t>;
}

extern "C" void* eq_prefix_fold_kernel() {
    return (void*)eqPrefixFold;
}

extern "C" void* eq_product_fix_and_sum_base_64_coop_kernel() {
    return (void*)eqProductFixAndSumAsPolyCoop<felt_t>;
}

extern "C" void* eq_product_fix_and_sum_ext_64_coop_kernel() {
    return (void*)eqProductFixAndSumAsPolyCoop<ext_t>;
}
