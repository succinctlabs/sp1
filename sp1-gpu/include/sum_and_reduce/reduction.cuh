#pragma once

#include <cuda/atomic>
#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

#include "fields/kb31_extension_t.cuh"
#include "fields/kb31_t.cuh"
#include "runtime/exception.cuh"

namespace cg = cooperative_groups;

template <typename Ty>
struct AddOpFinalReduce {
    template <typename TyGroup>
    __device__ __forceinline__ static void
    final_block_reduction_async(const TyGroup& group, Ty* dst, Ty val);
};

template <typename Ty>
struct AddOp {
    __device__ __forceinline__ Ty initial() const { return Ty::zero(); }

    __device__ __forceinline__ Ty operator()(const Ty arg1, const Ty arg2) const {
        return arg1 + arg2;
    }

    __device__ __forceinline__ void evalAssign(Ty& arg1, const Ty arg2) const { arg1 += arg2; }

    template <typename TyGroup>
    __device__ __forceinline__ Ty reduce(const TyGroup& group, Ty val) {
        return cg::reduce(group, val, cg::plus<Ty>());
    }

    template <typename TyGroup>
    __device__ __forceinline__ void
    final_block_reduction_async(const TyGroup& group, Ty* dst, Ty val) {
        return AddOpFinalReduce<Ty>::final_block_reduction_async(group, dst, val);
    }
};

template <typename F, typename TyOp, typename TyBlock, typename TyTile>
__device__ F
partialBlockReduce(const TyBlock& block, const TyTile& tile, F val, F* shared, TyOp&& op) {
    // Warp-level reduction within tiles
    val = op.reduce(tile, val);

    // Only the first thread of each warp writes to shared memory
    if (tile.thread_rank() == 0) {
        shared[tile.meta_group_rank()] = val;
    }
    block.sync(); // Synchronize after warp-level reduction

    // Perform tree-based reduction on shared memory
    for (int stride = (block.size() / tile.size()) / 2; stride > 0; stride /= 2) {
        if (block.thread_rank() < stride) {
            op.evalAssign(shared[block.thread_rank()], shared[block.thread_rank() + stride]);
        }
        block.sync(); // Synchronize after each step
    }

    return shared[0];
}

template <typename F, typename TyOp>
__global__ void partialBlockReduceKernel(F* partial, F* A, size_t width, size_t height, TyOp op);

template <typename F, typename TyOp>
__global__ void blockReduce(F* A, F* result, size_t width, size_t height, TyOp op);

template <>
struct AddOpFinalReduce<kb31_t> {
    template <typename TyGroup>
    __device__ __forceinline__ static void
    final_block_reduction_async(const TyGroup& group, kb31_t* dst, kb31_t val) {
        cuda::atomic_ref<kb31_t, cuda::thread_scope_block> atomic(dst[0]);
        // reduce thread sums across the tile, add the result to the atomic
        return cg::reduce_update_async(group, atomic, val, cg::plus<kb31_t>());
    }
};

template <>
struct AddOpFinalReduce<kb31_extension_t> {
    template <typename TyGroup>
    __device__ __forceinline__ static void
    final_block_reduction_async(const TyGroup& group, kb31_extension_t* dst, kb31_extension_t val) {
// Split the extension into a slice of base field elements and make a separate atomic update.
#pragma unroll
        for (int j = 0; j < kb31_extension_t::D; j++) {
            cuda::atomic_ref<kb31_t, cuda::thread_scope_block> atomic(dst[0].value[j]);
            cg::reduce_update_async(group, atomic, val.value[j], cg::plus<kb31_t>());
        }
    }
};

extern "C" void* koala_bear_sum_block_reduce_kernel();

extern "C" void* koala_bear_sum_partial_block_reduce_kernel();

extern "C" void* koala_bear_extension_sum_block_reduce_kernel();

extern "C" void* koala_bear_extension_sum_partial_block_reduce_kernel();
