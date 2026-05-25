#pragma once

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

// Block-level reduction of one F-typed value per thread to one F per block.
//
// Returns `shared[0]` to every thread. Despite that, the contract is:
// **only `block.thread_rank() == 0`'s return value is valid**; other
// threads read the same global address but it isn't a real broadcast —
// the next call to `partialBlockReduce` (or any other `shared[]` writer)
// races the late-thread reads. Callers that need the value on every
// thread must explicitly broadcast (e.g. write to `shared[0]` then
// `block.sync()`).
//
// Back-to-back calls *must* `block.sync()` between them: this function
// ends with `block.sync()` inside the tree loop, then a non-synced load
// of `shared[0]`, so a slow thread's load can otherwise race the next
// call's `shared[meta_group_rank()] = val` write.
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

    // Tree-based reduction over the N = block.size() / tile.size() warp partials.
    //
    // The simple `for (stride = N/2; stride > 0; stride /= 2)` loop is only
    // correct when N is a power of 2; for e.g. N = 3 it folds slot 1 into 0 and
    // then exits with `shared[2]` never added in (silent undercount).
    //
    // Fix (smallest blast radius — does not change the caller-visible shmem
    // contract of N slots): on the first pass fold the "tail" elements
    // `[pow2, N)` into `[0, N - pow2)`, leaving `pow2` valid partials, then run
    // the regular power-of-2 tree reduction. Since pow2 is the largest
    // power-of-2 <= N we have N - pow2 < pow2, so the writes don't overlap.
    const int n = block.size() / tile.size();
    int pow2 = 1;
    while ((pow2 << 1) <= n) {
        pow2 <<= 1;
    }
    if (pow2 < n) {
        const int tail = n - pow2;
        if (block.thread_rank() < tail) {
            shared[block.thread_rank()] += shared[block.thread_rank() + pow2];
        }
        block.sync();
    }

    // Perform tree-based reduction on shared memory
    for (int stride = pow2 / 2; stride > 0; stride /= 2) {
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

// Test-only kernel exercising `partialBlockReduce` with one block. Each thread
// contributes `input[threadIdx.x]` and the per-block sum is written to
// `output[0]`. Used to verify correctness for non-power-of-2 warp counts.
extern "C" void* partial_block_reduce_test_kernel_felt();