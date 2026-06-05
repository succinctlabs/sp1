#include "config.cuh"
#include "two_stage_eq_product_sumcheck/two_stage_eq_product_sumcheck.cuh"

// Two-stage-GKR Option 2 kernels.  Initial scope: K_1 = K_2 = 8 (one split).  See the
// header for the algorithmic overview.

// =================================================================================
// Build B_j[i] = ∏_{j'=0..K_1} eq(z_{j K_1 + j'}, p_{j K_1 + j'}[i])
// =================================================================================
//
// One thread per (i, j) pair.  For each j', read p_kk[i] (base) and combine with the
// precomputed (a_kk, b_kk) = (1 − z_kk, 2 z_kk − 1) into the ext factor.  Output is
// col-major K_2 × height; input is col-major K × height.
//
// Coalescing: idx = i + j·height ⇒ consecutive idx → consecutive i (same j), so per
// warp the K_1 strided reads at fixed j' all hit one cache line.
template <int K1, int K2>
__global__ void buildBMles(
    ext_t* __restrict__ b_mles,
    const felt_t* __restrict__ p_mles,
    const ext_t* __restrict__ a,
    const ext_t* __restrict__ b,
    size_t height) {
    size_t total = height * (size_t)K2;
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x; idx < total;
         idx += stride) {
        size_t i = idx % height;
        int j = (int)(idx / height);

        ext_t prod = ext_t::one();
#pragma unroll
        for (int jp = 0; jp < K1; ++jp) {
            int kk = j * K1 + jp;
            felt_t p = felt_t::load(p_mles, (size_t)kk * height + i);
            ext_t a_kk = ext_t::load(a, kk);
            ext_t b_kk = ext_t::load(b, kk);
            ext_t factor = a_kk + b_kk * p;
            prod = prod * factor;
        }
        ext_t::store(b_mles, (size_t)j * height + i, prod);
    }
}

// =================================================================================
// Stage 1 — eq-prefixed degree-(K + 1) product over K MLEs (here K = K_2).
// =================================================================================
//
// Direct K-templated lift of the Option 1 `eqProductSumAsPolyCoop` / `…FixAndSum…`
// kernels.  Bodies are unchanged; only `K` becomes a template parameter so the host
// can dispatch K_2 ∈ {2, 4, 8, 16, 32} as needed.  Stage 1 uses these kernels with
// (a, b) = (0, 1), so the factor `a + b·p` is the MLE value itself.

template <typename F, int K>
__global__ void eqProductSumAsPolyCoopT(
    ext_t* __restrict__ result,
    const F* __restrict__ mles,
    const ext_t* __restrict__ eq_prefix,
    const ext_t* __restrict__ a,
    const ext_t* __restrict__ b,
    size_t numXTop) {
    constexpr int BLOCK_SIZE = 256;
    constexpr int TILES_PER_BLOCK = BLOCK_SIZE / K;
    static_assert(TILES_PER_BLOCK * K == BLOCK_SIZE, "K must divide BLOCK_SIZE");

    int tile_id = threadIdx.x / K;
    int eval_idx = threadIdx.x % K;

    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    __shared__ ext_t shared_buf[TILES_PER_BLOCK * 2 * K];

    ext_t eval_acc = ext_t::zero();

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
            ext_t u_j = a_j + b_j * p_lo;
            ext_t v_j = b_j * d;

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

        __syncthreads();
    }

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

template <typename F, int K>
__global__ void eqProductFixAndSumAsPolyCoopT(
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
    constexpr int BLOCK_SIZE = 256;
    constexpr int TILES_PER_BLOCK = BLOCK_SIZE / K;
    static_assert(TILES_PER_BLOCK * K == BLOCK_SIZE, "K must divide BLOCK_SIZE");

    int tile_id = threadIdx.x / K;
    int eval_idx = threadIdx.x % K;

    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    size_t outputHeight = inputHeight >> 1;
    size_t numXTop = outputHeight >> 1;

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

// =================================================================================
// Stage 2 — degree-(K_1 + 1) sumcheck with K_2 outer sum.
// =================================================================================
//
// Per round we evaluate h_r(t) at K_1 kernel points t ∈ {0, 2, 3, …, K_1}:
//   h_r(t) = ∑_y E_r(y) · ∑_{j=1..K_2} w_j · ∏_{j' = 0..K_1}
//             (a_{jK_1+j'} + b_{jK_1+j'} · p_{jK_1+j'}(y, t)).
//
// Cooperative layout: K_1 threads per tile, TILES_PER_BLOCK = 256 / K_1 tiles per block.
// Each tile handles one x_top.  Per j ∈ [0, K_2):
//   * Thread eval_idx loads p_{jK_1+eval_idx}(y, ·), computes (u_{kk}, v_{kk}).
//     Thread eval_idx = 0 also multiplies in w_j so it propagates through the K_1-product
//     via the j' = 0 factor.
//   * __syncthreads.  Each thread reads all K_1 (u, v) pairs from shared and forms its
//     eval-point's K_1-product over the K_1 factors.
//   * Add the product into the per-y eval-point accumulator.
//   * __syncthreads (before next j reuses shared).
// After the K_2 loop, multiply the per-y accumulator by E_r(y) (one ext × ext per eval
// point per y) and add into the cross-x accumulator.

template <typename F, int K1, int K2>
__global__ void stage2SumAsPolyCoop(
    ext_t* __restrict__ result,
    const F* __restrict__ mles,
    const ext_t* __restrict__ eq_prefix,
    const ext_t* __restrict__ a,
    const ext_t* __restrict__ b,
    const ext_t* __restrict__ w,
    size_t numXTop) {
    constexpr int BLOCK_SIZE = 256;
    constexpr int TILES_PER_BLOCK = BLOCK_SIZE / K1;
    static_assert(TILES_PER_BLOCK * K1 == BLOCK_SIZE, "K1 must divide BLOCK_SIZE");

    int tile_id = threadIdx.x / K1;
    int eval_idx = threadIdx.x % K1;

    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    // Shared layout: per tile, 2·K_1 ext slots for (u, v) pairs in the current phase.
    // Re-used at block end for the cross-tile reduction (K_1 · TILES_PER_BLOCK slots,
    // which equals 2·K_1·TILES_PER_BLOCK / 2 — same buffer size).
    __shared__ ext_t shared_buf[TILES_PER_BLOCK * 2 * K1];

    ext_t eval_acc = ext_t::zero();

    size_t x_top_step = (size_t)gridDim.x * TILES_PER_BLOCK;
    size_t block_start = (size_t)blockIdx.x * TILES_PER_BLOCK;
    size_t block_iter_count =
        (block_start >= numXTop) ? 0 : ((numXTop - 1 - block_start) / x_top_step + 1);

    size_t inputHeight = numXTop << 1;

    for (size_t iter = 0; iter < block_iter_count; ++iter) {
        size_t x = block_start + tile_id + iter * x_top_step;
        bool active = x < numXTop;

        size_t lo_idx = x << 1;
        size_t hi_idx = lo_idx + 1;

        ext_t per_y = ext_t::zero();

#pragma unroll
        for (int j = 0; j < K2; ++j) {
            if (active) {
                int kk = j * K1 + eval_idx;
                F p_lo = F::load(mles, (size_t)kk * inputHeight + lo_idx);
                F p_hi = F::load(mles, (size_t)kk * inputHeight + hi_idx);
                ext_t a_kk = ext_t::load(a, kk);
                ext_t b_kk = ext_t::load(b, kk);
                F d = p_hi - p_lo;
                ext_t u_kk = a_kk + b_kk * p_lo;
                ext_t v_kk = b_kk * d;

                if (eval_idx == 0) {
                    ext_t w_j = ext_t::load(w, j);
                    u_kk = w_j * u_kk;
                    v_kk = w_j * v_kk;
                }

                size_t shared_tile_base = (size_t)tile_id * 2 * K1;
                ext_t::store(shared_buf, shared_tile_base + 2 * eval_idx + 0, u_kk);
                ext_t::store(shared_buf, shared_tile_base + 2 * eval_idx + 1, v_kk);
            }

            __syncthreads();

            if (active) {
                size_t shared_tile_base = (size_t)tile_id * 2 * K1;
                ext_t prod;
                {
                    ext_t u0 = ext_t::load(shared_buf, shared_tile_base + 0);
                    ext_t v0 = ext_t::load(shared_buf, shared_tile_base + 1);
                    prod = u0 + v0 * my_t_kb;
                }
#pragma unroll
                for (int jj = 1; jj < K1; ++jj) {
                    ext_t u = ext_t::load(shared_buf, shared_tile_base + 2 * jj);
                    ext_t v = ext_t::load(shared_buf, shared_tile_base + 2 * jj + 1);
                    ext_t factor = u + v * my_t_kb;
                    prod = prod * factor;
                }
                per_y = per_y + prod;
            }

            __syncthreads();
        }

        if (active) {
            ext_t eq_val = ext_t::load(eq_prefix, x);
            eval_acc += eq_val * per_y;
        }
    }

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

// Fused fold + eq-prefix update + next-round sum-as-poly for stage 2.
//
// One pass over the K = K_1·K_2 input MLE columns: fold each by alpha, write out the
// folded ext-typed result, update the eq prefix via pair-sum + scalar, and compute the
// next round's K_1 kernel evals.  Saves one full K × N/2 ext read per fused round vs
// running fold + sum_as_poly as separate kernels.
template <typename F, int K1, int K2>
__global__ void stage2FixAndSumCoop(
    const F* __restrict__ input_mles,
    ext_t* __restrict__ output_mles,
    const ext_t* __restrict__ input_eq,
    ext_t* __restrict__ output_eq,
    const ext_t* __restrict__ a,
    const ext_t* __restrict__ b,
    const ext_t* __restrict__ w,
    ext_t alpha,
    ext_t eq_scalar,
    ext_t* __restrict__ univariate_result,
    size_t inputHeight) {
    constexpr int BLOCK_SIZE = 256;
    constexpr int TILES_PER_BLOCK = BLOCK_SIZE / K1;
    static_assert(TILES_PER_BLOCK * K1 == BLOCK_SIZE, "K1 must divide BLOCK_SIZE");

    int tile_id = threadIdx.x / K1;
    int eval_idx = threadIdx.x % K1;

    kb31_t my_t_kb =
        (eval_idx == 0) ? kb31_t::zero() : kb31_t::from_canonical_u32((uint32_t)(eval_idx + 1));

    size_t outputHeight = inputHeight >> 1;
    size_t numXTop = outputHeight >> 1;

    __shared__ ext_t shared_buf[TILES_PER_BLOCK * 2 * K1];

    ext_t eval_acc = ext_t::zero();

    size_t x_top_step = (size_t)gridDim.x * TILES_PER_BLOCK;
    size_t block_start = (size_t)blockIdx.x * TILES_PER_BLOCK;
    size_t block_iter_count =
        (block_start >= numXTop) ? 0 : ((numXTop - 1 - block_start) / x_top_step + 1);

    for (size_t iter = 0; iter < block_iter_count; ++iter) {
        size_t x_top = block_start + tile_id + iter * x_top_step;
        bool active = x_top < numXTop;

        size_t base_in = x_top << 2;
        size_t lo_out = x_top << 1;
        size_t hi_out = lo_out + 1;

        // Eq prefix transition: every thread of the tile computes new_eq itself (cheap —
        // 2 ext-loads + 1 ext-add + 1 ext-mul, same x_top across the tile so the reads
        // coalesce within a warp).  Only eval_idx = 0 writes the result to output_eq.
        // Holding new_eq in a per-thread register avoids a cross-tile broadcast that
        // would have to sit outside `if (active)` for correctness.
        ext_t new_eq = ext_t::zero();
        if (active) {
            ext_t eq_lo = ext_t::load(input_eq, 2 * x_top);
            ext_t eq_hi = ext_t::load(input_eq, 2 * x_top + 1);
            new_eq = (eq_lo + eq_hi) * eq_scalar;
            if (eval_idx == 0) {
                ext_t::store(output_eq, x_top, new_eq);
            }
        }

        ext_t per_y = ext_t::zero();

#pragma unroll
        for (int j = 0; j < K2; ++j) {
            if (active) {
                int kk = j * K1 + eval_idx;

                // Fold one of the K columns by alpha: produce v_lo (at folded 2·x_top)
                // and v_hi (at folded 2·x_top + 1).
                F a0 = F::load(input_mles, (size_t)kk * inputHeight + base_in);
                F a1 = F::load(input_mles, (size_t)kk * inputHeight + base_in + 1);
                F a2 = F::load(input_mles, (size_t)kk * inputHeight + base_in + 2);
                F a3 = F::load(input_mles, (size_t)kk * inputHeight + base_in + 3);

                ext_t v_lo = alpha.interpolateLinear(a1, a0);
                ext_t v_hi = alpha.interpolateLinear(a3, a2);

                ext_t::store(output_mles, (size_t)kk * outputHeight + lo_out, v_lo);
                ext_t::store(output_mles, (size_t)kk * outputHeight + hi_out, v_hi);

                // Build the (u, v) for this j' at the new round's x_top.
                ext_t a_kk = ext_t::load(a, kk);
                ext_t b_kk = ext_t::load(b, kk);
                ext_t d = v_hi - v_lo;
                ext_t u_kk = a_kk + b_kk * v_lo;
                ext_t v_kk = b_kk * d;

                if (eval_idx == 0) {
                    ext_t w_j = ext_t::load(w, j);
                    // Absorb w_j into (u_0, v_0) — propagates through the K_1-product.
                    // For j = 0 also absorb new_eq if we wanted to fold the prefix in
                    // here, but we use the end-scale strategy instead.
                    u_kk = w_j * u_kk;
                    v_kk = w_j * v_kk;
                }

                size_t shared_tile_base = (size_t)tile_id * 2 * K1;
                ext_t::store(shared_buf, shared_tile_base + 2 * eval_idx + 0, u_kk);
                ext_t::store(shared_buf, shared_tile_base + 2 * eval_idx + 1, v_kk);
            }

            __syncthreads();

            if (active) {
                size_t shared_tile_base = (size_t)tile_id * 2 * K1;
                ext_t prod;
                {
                    ext_t u0 = ext_t::load(shared_buf, shared_tile_base + 0);
                    ext_t v0 = ext_t::load(shared_buf, shared_tile_base + 1);
                    prod = u0 + v0 * my_t_kb;
                }
#pragma unroll
                for (int jj = 1; jj < K1; ++jj) {
                    ext_t u = ext_t::load(shared_buf, shared_tile_base + 2 * jj);
                    ext_t v = ext_t::load(shared_buf, shared_tile_base + 2 * jj + 1);
                    ext_t factor = u + v * my_t_kb;
                    prod = prod * factor;
                }
                per_y = per_y + prod;
            }

            __syncthreads();
        }

        if (active) {
            eval_acc += new_eq * per_y;
        }
    }

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

// =================================================================================
// FFI exports — all 5 (K_1, K_2) splits of K = 64: (2, 32), (4, 16), (8, 8), (16, 4),
// (32, 2).  Stage 1 needs K_2 ∈ {2, 4, 8, 16, 32}; stage 2 needs the full (K_1, K_2)
// pair.
// =================================================================================

#define BUILD_B_KERNEL(K1, K2)                                                                     \
    extern "C" void* build_b_mles_##K1##_##K2##_kernel() { return (void*)buildBMles<K1, K2>; }

#define STAGE1_KERNELS(K2)                                                                         \
    extern "C" void* two_stage_stage1_sum_as_poly_ext_##K2##_kernel() {                            \
        return (void*)eqProductSumAsPolyCoopT<ext_t, K2>;                                          \
    }                                                                                              \
    extern "C" void* two_stage_stage1_fix_and_sum_ext_##K2##_kernel() {                            \
        return (void*)eqProductFixAndSumAsPolyCoopT<ext_t, K2>;                                    \
    }

#define STAGE2_KERNELS(K1, K2)                                                                     \
    extern "C" void* two_stage_stage2_sum_as_poly_base_##K1##_##K2##_kernel() {                    \
        return (void*)stage2SumAsPolyCoop<felt_t, K1, K2>;                                         \
    }                                                                                              \
    extern "C" void* two_stage_stage2_fix_and_sum_base_##K1##_##K2##_kernel() {                    \
        return (void*)stage2FixAndSumCoop<felt_t, K1, K2>;                                         \
    }                                                                                              \
    extern "C" void* two_stage_stage2_fix_and_sum_ext_##K1##_##K2##_kernel() {                     \
        return (void*)stage2FixAndSumCoop<ext_t, K1, K2>;                                          \
    }

// (2, 32)
BUILD_B_KERNEL(2, 32)
STAGE1_KERNELS(32)
STAGE2_KERNELS(2, 32)

// (4, 16)
BUILD_B_KERNEL(4, 16)
STAGE1_KERNELS(16)
STAGE2_KERNELS(4, 16)

// (8, 8)
BUILD_B_KERNEL(8, 8)
STAGE1_KERNELS(8)
STAGE2_KERNELS(8, 8)

// (16, 4)
BUILD_B_KERNEL(16, 4)
STAGE1_KERNELS(4)
STAGE2_KERNELS(16, 4)

// (32, 2)
BUILD_B_KERNEL(32, 2)
STAGE1_KERNELS(2)
STAGE2_KERNELS(32, 2)
