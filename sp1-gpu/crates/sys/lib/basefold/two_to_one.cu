#include "basefold/two_to_one.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>
#include <cstdint>

namespace cg = cooperative_groups;

// ---------------------------------------------------------------------------
// Two-to-one Option-2 (batched sumcheck) per-round sum-as-poly.
//
// Computes two accumulators per round:
//   G_T1(0) = Σ_j eq_z [2j] · h[2j]
//   G_T2(0) = Σ_j eq_zp[2j] · h[2j]
//
// Each `G(t) = eq(z_round, t) · H(t)` with `H` linear; combined with the
// previous-round sub-claim (claim_t1 / claim_t2) this determines the full
// degree-2 round univariate per track (Gruen + 1-accumulator-per-track).
//
// Per-thread inner work: 2 ext multiplies + 2 ext adds per `rest`.  Block
// partials reduced via `partialBlockReduce`, written to
//   block_partial[blk·2 + {0, 1}] = (T1_0, T2_0)
// for the host to sum across blocks.
// ---------------------------------------------------------------------------
__global__ void twoToOneSumAsPolyZero(
    const ext_t *__restrict__ eq_z_t,
    const ext_t *__restrict__ eq_zp_t,
    const ext_t *__restrict__ h_t,
    uint32_t half,
    ext_t *__restrict__ block_partial)
{
    const uint32_t stride = blockDim.x * gridDim.x;

    ext_t acc_t1 = ext_t::zero();
    ext_t acc_t2 = ext_t::zero();

    for (uint32_t rest = blockIdx.x * blockDim.x + threadIdx.x; rest < half;
         rest += stride) {
        const uint32_t lo = rest * 2u;
        const ext_t eq_z_lo = ext_t::load(eq_z_t, lo);
        const ext_t eq_zp_lo = ext_t::load(eq_zp_t, lo);
        const ext_t h_lo = ext_t::load(h_t, lo);
        acc_t1 += eq_z_lo * h_lo;
        acc_t2 += eq_zp_lo * h_lo;
    }

    extern __shared__ unsigned char shmem[];
    ext_t *shared = reinterpret_cast<ext_t *>(shmem);
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    ext_t sum_t1 = partialBlockReduce(block, tile, acc_t1, shared);
    ext_t sum_t2 = partialBlockReduce(block, tile, acc_t2, shared);

    if (threadIdx.x == 0) {
        const uint32_t base = blockIdx.x * 2u;
        ext_t::store(block_partial, base + 0u, sum_t1);
        ext_t::store(block_partial, base + 1u, sum_t2);
    }
}

extern "C" void *two_to_one_sum_as_poly_zero_kernel()
{
    return (void *)twoToOneSumAsPolyZero;
}
