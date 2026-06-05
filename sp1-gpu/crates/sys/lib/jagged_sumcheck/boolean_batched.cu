#include "jagged_sumcheck/boolean_batched.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>
#include <cstdint>

namespace cg = cooperative_groups;

// ---------------------------------------------------------------------------
// inc table — backward (MSB→LSB) width-4 BP for
//     inc(z, j) = (j = i + 1) ∧ (j ≤ num_real_cols − 1)
// at fixed extension point z (length c) and varying integer j ∈ [0, 2^c).
//
// State encoding: idx = carry + 2 · cso, four reachable states.  Suffix DP
// seeds state[2] = 1 (accepting end state), iterates layer c−1 → 0, returns
// state[3] (the BP's actual start state).
//
// Grid-stride over j; each thread handles ≥ 1 j and runs the c-layer DP in
// registers.
// ---------------------------------------------------------------------------
__global__ void booleanIncTable(
    const ext_t *__restrict__ z_pt,   // length c, MSB-first (z_pt[0] = MSB)
    uint32_t c,
    uint32_t threshold,                // = num_real_cols − 1
    uint32_t two_c,                    // = 1 << c
    ext_t *__restrict__ out)           // length two_c
{
    const uint32_t stride = blockDim.x * gridDim.x;

    for (uint32_t j = blockIdx.x * blockDim.x + threadIdx.x; j < two_c;
         j += stride) {
        ext_t state[4];
        state[0] = ext_t::zero();
        state[1] = ext_t::zero();
        state[2] = ext_t::one();
        state[3] = ext_t::zero();

        // Suffix DP: layer = c−1 (MSB) down to 0 (LSB).
        for (int layer = (int)c - 1; layer >= 0; --layer) {
            // z_pt convention matches Point::from_usize: bit `b` (LSB) lives
            // at z_pt[c − 1 − b], so layer `b` reads z_pt[c − 1 − layer].
            const ext_t i_b = ext_t::load(z_pt, c - 1u - (uint32_t)layer);
            const uint32_t j_b = (j >> (uint32_t)layer) & 1u;
            const uint32_t n_b = (threshold >> (uint32_t)layer) & 1u;

            ext_t new_state[4];
#pragma unroll
            for (uint32_t s_in = 0u; s_in < 4u; ++s_in) {
                const uint32_t carry_in = s_in & 1u;
                const uint32_t cso_in = (s_in >> 1) & 1u;

                // Carry-adder check forces i_b_input = j_b ⊕ carry_in for the
                // only non-FAIL transition (since j_b is integer-fixed here).
                const uint32_t valid_i_b = j_b ^ carry_in;
                const ext_t factor = (valid_i_b == 0u)
                                         ? (ext_t::one() - i_b)
                                         : i_b;

                const uint32_t carry_out = valid_i_b & carry_in;
                uint32_t cso_out;
                if (j_b < n_b) {
                    cso_out = 1u;
                } else if (j_b > n_b) {
                    cso_out = 0u;
                } else {
                    cso_out = cso_in;
                }

                const uint32_t state_out = carry_out + 2u * cso_out;
                new_state[s_in] = factor * state[state_out];
            }
            state[0] = new_state[0];
            state[1] = new_state[1];
            state[2] = new_state[2];
            state[3] = new_state[3];
        }

        ext_t::store(out, j, state[3]);
    }
}

extern "C" void *boolean_inc_table_kernel()
{
    return (void *)booleanIncTable;
}

// ---------------------------------------------------------------------------
// Reduced-register variant computing 4 accumulators at t ∈ {0, 1/2} for the
// two summands T1 = inc·q and T2 = eq·(α·Q + (α²−α)·q) separately, so the
// host can reconstruct the degree-3 round polynomial via
//   - the prev-round-claim trick (T1's claim splits + T2's claim splits), and
//   - Gruen's eq-factor trick on T2 (G_T2(t) = eq(z_round, t)·K(t),
//     K degree-2).
//
// Per (rest, b) inner work: 4 muls + 2 squarings + 1 add per b (down from
// 8 muls + 4 squarings + 3 adds in `booleanSumAsPoly`).  No p/inc/eq
// extrapolations to {−1, 2} — only to t = 1/2 (single `(a + b) · ½`).
//
// Output layout: `block_partial[blk·4 + {0,1,2,3}] = (T1_0, T1_half,
// T2_0, T2_half)` block partials.
// ---------------------------------------------------------------------------
__global__ void booleanSumAsPolyHalf(
    const ext_t *__restrict__ inc_t,
    const ext_t *__restrict__ eq_t,
    const ext_t *__restrict__ p_t,
    const ext_t *__restrict__ beta_pows,
    ext_t alpha,
    ext_t half_inv,                       // = 1/2 in EF, precomputed on host
    uint32_t half,
    ext_t *__restrict__ block_partial)
{
    const uint32_t two_half = half * 2u;
    const uint32_t stride = blockDim.x * gridDim.x;
    const ext_t aa_minus_a = alpha * alpha - alpha;

    ext_t e0_t1 = ext_t::zero();
    ext_t eh_t1 = ext_t::zero();
    ext_t e0_t2 = ext_t::zero();
    ext_t eh_t2 = ext_t::zero();

    for (uint32_t rest = blockIdx.x * blockDim.x + threadIdx.x; rest < half;
         rest += stride) {
        const uint32_t lo = rest * 2u;
        const uint32_t hi = lo + 1u;

        const ext_t inc_0 = ext_t::load(inc_t, lo);
        const ext_t inc_1 = ext_t::load(inc_t, hi);
        const ext_t eq_0 = ext_t::load(eq_t, lo);
        const ext_t eq_1 = ext_t::load(eq_t, hi);
        const ext_t inc_h = (inc_0 + inc_1) * half_inv;
        const ext_t eq_h = (eq_0 + eq_1) * half_inv;

        ext_t sp_0 = ext_t::zero();
        ext_t sp_h = ext_t::zero();
        ext_t sq_0 = ext_t::zero();
        ext_t sq_h = ext_t::zero();

#pragma unroll 8
        for (uint32_t b = 0u; b < 32u; ++b) {
            const ext_t p_0 = ext_t::load(p_t, b * two_half + lo);
            const ext_t p_1 = ext_t::load(p_t, b * two_half + hi);
            const ext_t p_h = (p_0 + p_1) * half_inv;
            const ext_t bp = ext_t::load(beta_pows, b);

            sp_0 += bp * p_0;
            sp_h += bp * p_h;
            sq_0 += bp * p_0 * p_0;
            sq_h += bp * p_h * p_h;
        }

        e0_t1 += inc_0 * sp_0;
        eh_t1 += inc_h * sp_h;
        e0_t2 += eq_0 * (alpha * sq_0 + aa_minus_a * sp_0);
        eh_t2 += eq_h * (alpha * sq_h + aa_minus_a * sp_h);
    }

    extern __shared__ unsigned char shmem[];
    ext_t *shared = reinterpret_cast<ext_t *>(shmem);
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    ext_t s0_t1 = partialBlockReduce(block, tile, e0_t1, shared);
    ext_t sh_t1 = partialBlockReduce(block, tile, eh_t1, shared);
    ext_t s0_t2 = partialBlockReduce(block, tile, e0_t2, shared);
    ext_t sh_t2 = partialBlockReduce(block, tile, eh_t2, shared);

    if (threadIdx.x == 0) {
        const uint32_t base = blockIdx.x * 4u;
        ext_t::store(block_partial, base + 0u, s0_t1);
        ext_t::store(block_partial, base + 1u, sh_t1);
        ext_t::store(block_partial, base + 2u, s0_t2);
        ext_t::store(block_partial, base + 3u, sh_t2);
    }
}

extern "C" void *boolean_sum_as_poly_half_kernel()
{
    return (void *)booleanSumAsPolyHalf;
}

// ---------------------------------------------------------------------------
// Build the 32 curr-bit MLEs directly on device, in `[32 (b outer), 2^c]`
// flat layout, as `ext_t` values (Boolean 0/1 promoted to extension).
// Each thread writes one (b, col) cell.
// ---------------------------------------------------------------------------
__global__ void booleanCurrBitsExt(
    const uint32_t *__restrict__ prefix_sums,
    uint32_t num_real_cols,
    uint32_t two_c,
    ext_t *__restrict__ out)
{
    const uint32_t col = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t b = blockIdx.y * blockDim.y + threadIdx.y;
    if (col >= two_c || b >= 32u) return;

    bool bit_set = false;
    if (col < num_real_cols) {
        bit_set = ((prefix_sums[col] >> b) & 1u) != 0u;
    }
    const ext_t val = bit_set ? ext_t::one() : ext_t::zero();
    ext_t::store(out, b * two_c + col, val);
}

extern "C" void *boolean_curr_bits_ext_kernel()
{
    return (void *)booleanCurrBitsExt;
}
