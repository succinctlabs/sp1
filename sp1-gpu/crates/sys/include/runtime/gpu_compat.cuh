// GPU compatibility header for CUDA/HIP dual-target compilation.
// Include this instead of <cuda_runtime.h> or <cooperative_groups.h>.
#pragma once

#ifdef __HIPCC__
#include <hip/hip_runtime.h>
// Don't include hip_cooperative_groups.h - it fails with custom field types.
// Provide our own minimal cooperative_groups shims.
#else
#include <cuda_runtime.h>
#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>
#endif

#ifdef __HIPCC__
// Minimal cooperative_groups compatibility layer for HIP.

namespace cooperative_groups {

class thread_block {
public:
    __device__ static thread_block this_thread_block() { return thread_block(); }
    __device__ unsigned int size() const { return blockDim.x * blockDim.y * blockDim.z; }
    __device__ unsigned int thread_rank() const {
        return threadIdx.x + threadIdx.y * blockDim.x + threadIdx.z * blockDim.x * blockDim.y;
    }
    __device__ void sync() const { __syncthreads(); }
};

template <unsigned int Size>
class thread_block_tile {
public:
    __device__ unsigned int size() const { return Size; }
    __device__ unsigned int thread_rank() const { return threadIdx.x % Size; }
    __device__ unsigned int meta_group_rank() const { return threadIdx.x / Size; }
    __device__ void sync() const { }

    template <typename T>
    __device__ T shfl(T val, int srcLane) const {
        T result;
        uint32_t* src = reinterpret_cast<uint32_t*>(&val);
        uint32_t* dst = reinterpret_cast<uint32_t*>(&result);
        #pragma unroll
        for (int i = 0; i < (int)(sizeof(T) / sizeof(uint32_t)); i++)
            dst[i] = __shfl(src[i], srcLane, Size);
        return result;
    }

    template <typename T>
    __device__ T shfl_down(T val, unsigned int delta) const {
        T result;
        uint32_t* src = reinterpret_cast<uint32_t*>(&val);
        uint32_t* dst = reinterpret_cast<uint32_t*>(&result);
        #pragma unroll
        for (int i = 0; i < (int)(sizeof(T) / sizeof(uint32_t)); i++)
            dst[i] = __shfl_down(src[i], delta, Size);
        return result;
    }

    template <typename T>
    __device__ T shfl_xor(T val, int laneMask) const {
        T result;
        uint32_t* src = reinterpret_cast<uint32_t*>(&val);
        uint32_t* dst = reinterpret_cast<uint32_t*>(&result);
        #pragma unroll
        for (int i = 0; i < (int)(sizeof(T) / sizeof(uint32_t)); i++)
            dst[i] = __shfl_xor(src[i], laneMask, Size);
        return result;
    }
};

__device__ inline thread_block this_thread_block() {
    return thread_block::this_thread_block();
}

template <unsigned int Size>
__device__ inline thread_block_tile<Size> tiled_partition(const thread_block&) {
    return thread_block_tile<Size>();
}

template <typename T>
struct plus {
    __device__ T operator()(T a, T b) const { return a + b; }
};

template <typename TyGroup, typename T, typename Op>
__device__ __forceinline__ T reduce(const TyGroup& group, T val, Op op) {
    for (unsigned int offset = group.size() / 2; offset > 0; offset /= 2) {
        T other = group.shfl_down(val, offset);
        val = op(val, other);
    }
    return val;
}

} // namespace cooperative_groups

#endif

namespace cg = cooperative_groups;
