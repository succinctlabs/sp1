// Device-side aggregation of per-block (per-eval-point) partials.
// See `aggregate.cuh` for the contract.

#include "zerocheck/aggregate.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

namespace {

__global__ void zerocheck_aggregate_partials(
    const ext_t* __restrict__ partials,
    uint32_t total_slots,
    ext_t* __restrict__ totals  // 3 ext_t outputs
) {
    // Grid-stride over `block` triples (3 slots each), accumulating one
    // ext_t per eval point per thread.
    const uint32_t n_triples = total_slots / 3u;
    ext_t acc0 = ext_t::zero();
    ext_t acc1 = ext_t::zero();
    ext_t acc2 = ext_t::zero();
    for (uint32_t b = threadIdx.x; b < n_triples; b += blockDim.x) {
        acc0 += ext_t::load(partials, b * 3u + 0u);
        acc1 += ext_t::load(partials, b * 3u + 1u);
        acc2 += ext_t::load(partials, b * 3u + 2u);
    }

    extern __shared__ unsigned char smem[];
    ext_t* shared = reinterpret_cast<ext_t*>(smem);
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    ext_t t0 = partialBlockReduce(block, tile, acc0, shared);
    block.sync();
    ext_t t1 = partialBlockReduce(block, tile, acc1, shared);
    block.sync();
    ext_t t2 = partialBlockReduce(block, tile, acc2, shared);

    if (threadIdx.x == 0) {
        ext_t::store(totals, 0, t0);
        ext_t::store(totals, 1, t1);
        ext_t::store(totals, 2, t2);
    }
}

}  // namespace

extern "C" void* zerocheck_aggregate_partials_kernel() {
    return (void*)zerocheck_aggregate_partials;
}
