#pragma once

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

template <typename F, typename TyBlock, typename TyTile>
__device__ __forceinline__ F
partialBlockReduce(const TyBlock& block, const TyTile& tile, F val, F* shared) {
    // Warp-level reduction within tiles
    val = cg::reduce(tile, val, cg::plus<F>());

    // Only the first thread of each warp writes to shared memory
    if (tile.thread_rank() == 0) {
        shared[tile.meta_group_rank()] = val;
    }
    // Synchronize after warp-level reduction
    block.sync();

    // Perform tree-based reduction on shared memory
    for (int stride = (block.size() / tile.size()) / 2; stride > 0; stride /= 2) {
        if (block.thread_rank() < stride) {
            shared[block.thread_rank()] += shared[block.thread_rank() + stride];
        }
        // Synchronize after each step
        block.sync();
    }
    return shared[0];
}

// A reduction kernel for Felt
extern "C" void* reduce_kernel_felt();
// A reduction kernel for Ext
extern "C" void* reduce_kernel_ext();