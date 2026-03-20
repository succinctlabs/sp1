#pragma once

#include "fields/kb31_t.cuh"

// Helper to load a pair of adjacent elements. Specialized for kb31_t to use
// a single 8-byte vectorized (int2) load instead of two 4-byte scalar loads.
// This improves memory throughput when loading even/odd pairs for MLE folding.
template <typename F>
__device__ __forceinline__ void loadPair(const F* ptr, size_t idx, F& even, F& odd) {
    even = F::load(ptr, idx);
    odd = F::load(ptr, idx + 1);
}

#ifdef __CUDA_ARCH__
template <>
__device__ __forceinline__ void loadPair<kb31_t>(const kb31_t* ptr, size_t idx, kb31_t& even, kb31_t& odd) {
    int2 pair = *reinterpret_cast<const int2*>(&ptr[idx]);
    even.val = static_cast<uint32_t>(pair.x);
    odd.val = static_cast<uint32_t>(pair.y);
}
#endif
