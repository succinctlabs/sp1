// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef __SPPARK_UTIL_EXCEPTION_CUH__
#define __SPPARK_UTIL_EXCEPTION_CUH__

#include "exception.hpp"

#ifdef __HIPCC__
#include <hip/hip_runtime.h>
// CUDA→HIP type compatibility for AMD platform
using cudaError_t = hipError_t;
using cudaStream_t = hipStream_t;
using cudaEvent_t = hipEvent_t;
using cudaDeviceProp = hipDeviceProp_t;
#define cudaSuccess hipSuccess
#define cudaGetErrorString hipGetErrorString
#define cudaEventDisableTiming hipEventDisableTiming
#define cudaStreamNonBlocking hipStreamNonBlocking
#define cudaEventCreateWithFlags hipEventCreateWithFlags
#define cudaEventRecord hipEventRecord
#define cudaEventDestroy hipEventDestroy
#define cudaStreamCreateWithFlags hipStreamCreateWithFlags
#define cudaStreamDestroy hipStreamDestroy
#define cudaStreamWaitEvent hipStreamWaitEvent
#define cudaStreamSynchronize hipStreamSynchronize
// ROCm bug: hipMallocAsync/hipFreeAsync leak memory (pool never returns to OS).
// Use a caching allocator over synchronous hipMalloc/hipFree.
#include <unordered_map>
#include <vector>
#include <mutex>

static std::mutex g_sppark_alloc_mutex;
static std::unordered_map<size_t, std::vector<void*>> g_sppark_free_pool;
static std::unordered_map<void*, size_t> g_sppark_alloc_sizes;
static size_t g_sppark_cached_bytes = 0;

template<typename T>
static inline hipError_t cachedHipMallocSppark(T** p, size_t s, hipStream_t) {
    if (s == 0) { *p = nullptr; return hipSuccess; }
    std::lock_guard<std::mutex> lock(g_sppark_alloc_mutex);
    auto it = g_sppark_free_pool.find(s);
    if (it != g_sppark_free_pool.end() && !it->second.empty()) {
        *p = (T*)it->second.back();
        it->second.pop_back();
        g_sppark_cached_bytes -= s;
        return hipSuccess;
    }
    hipError_t err = hipMalloc((void**)p, s);
    if (err == hipSuccess) {
        g_sppark_alloc_sizes[(void*)*p] = s;
    }
    return err;
}

static inline hipError_t cachedHipFreeSppark(void* p, hipStream_t) {
    if (p == nullptr) return hipSuccess;
    std::lock_guard<std::mutex> lock(g_sppark_alloc_mutex);
    auto it = g_sppark_alloc_sizes.find(p);
    if (it != g_sppark_alloc_sizes.end()) {
        size_t s = it->second;
        if (g_sppark_cached_bytes + s <= 4ULL * 1024 * 1024 * 1024) {
            g_sppark_free_pool[s].push_back(p);
            g_sppark_cached_bytes += s;
            return hipSuccess;
        }
        g_sppark_alloc_sizes.erase(it);
    }
    return hipFree(p);
}

#define cudaMallocAsync cachedHipMallocSppark
#define cudaFreeAsync cachedHipFreeSppark
#define cudaMemcpyAsync hipMemcpyAsync
#define cudaMemsetAsync hipMemsetAsync
#define cudaMemcpyHostToDevice hipMemcpyHostToDevice
#define cudaMemcpyDeviceToHost hipMemcpyDeviceToHost
#define cudaMemcpyDeviceToDevice hipMemcpyDeviceToDevice
#define cudaMemcpyHostToHost hipMemcpyHostToHost
#define cudaLaunchKernel hipLaunchKernel
#define cudaGetDevice hipGetDevice
#define cudaGetDeviceCount hipGetDeviceCount
#define cudaSetDevice hipSetDevice
#define cudaDeviceSynchronize hipDeviceSynchronize
#define cudaGetDeviceProperties hipGetDeviceProperties
#define cudaMemGetInfo hipMemGetInfo
#define cudaMalloc hipMalloc
#define cudaFree hipFree
#define cudaMemcpy hipMemcpy
#define cudaMallocHost hipHostMalloc
#define cudaFreeHost hipHostFree
#define cudaStreamQuery hipStreamQuery
#define cudaEventQuery hipEventQuery
#define cudaLaunchHostFunc hipLaunchHostFunc
#define cudaEventSynchronize hipEventSynchronize
#define cudaEventElapsedTime hipEventElapsedTime
#define cudaMemset hipMemset
#define cudaDeviceGetMemPool hipDeviceGetMemPool
#define cudaMemPoolSetAttribute hipMemPoolSetAttribute
using cudaHostFn_t = hipHostFn_t;
#define cudaFuncAttributeMaxDynamicSharedMemorySize hipFuncAttributeMaxDynamicSharedMemorySize
#define cudaFuncSetAttribute hipFuncSetAttribute
#define cudaFuncGetAttributes hipFuncGetAttributes
#define cudaLaunchCooperativeKernel hipLaunchCooperativeKernel
#define cudaHostRegister hipHostRegister
#define cudaHostUnregister hipHostUnregister
#define cudaHostRegisterDefault hipHostRegisterDefault
#define cudaGetLastError hipGetLastError
#define cudaGetSymbolAddress hipGetSymbolAddress
#define cudaOccupancyMaxPotentialBlockSize hipOccupancyMaxPotentialBlockSize
#define cudaEventCreate hipEventCreate
#define cudaErrorMemoryAllocation hipErrorOutOfMemory
#define cudaErrorNotReady hipErrorNotReady
#define cudaMemPoolAttrReleaseThreshold hipMemPoolAttrReleaseThreshold
#define cudaDeviceGetDefaultMemPool hipDeviceGetDefaultMemPool
using cudaFuncAttributes = hipFuncAttributes;
using cudaMemPool_t = hipMemPool_t;
#endif

using cuda_error = sppark_error;

#define CUDA_UNWRAP_SPPARK(expr) do {                                  \
    cudaError_t code = expr;                                \
    if (code != cudaSuccess) {                              \
        auto file = std::strstr(__FILE__, "sppark");        \
        auto str = fmt("%s@%s:%d failed: \"%s\"", #expr,    \
                       file ? file : __FILE__, __LINE__,    \
                       cudaGetErrorString(code));           \
        throw cuda_error{-code, str};                       \
    }                                                       \
} while(0)

#endif
