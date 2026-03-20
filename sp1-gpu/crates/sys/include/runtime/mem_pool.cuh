
#pragma once

#ifdef __HIPCC__
#include <hip/hip_runtime.h>
using cudaMemPool_t = hipMemPool_t;
#define cudaDeviceGetDefaultMemPool hipDeviceGetDefaultMemPool
#define cudaDeviceGetMemPool hipDeviceGetMemPool
#define cudaMemPoolSetAttribute hipMemPoolSetAttribute
#define cudaMemPoolAttrReleaseThreshold hipMemPoolAttrReleaseThreshold
#endif

#include "runtime/exception.cuh"
#include <cstdint>

extern "C" rustCudaError_t cuda_device_get_default_mem_pool(cudaMemPool_t* memPool, int32_t device);
extern "C" rustCudaError_t cuda_device_get_mem_pool(cudaMemPool_t* memPool, int32_t device);
extern "C" rustCudaError_t
cuda_mem_pool_set_release_threshold(cudaMemPool_t memPool, uint64_t threshold);