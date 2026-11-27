
#pragma once

#include "runtime/exception.cuh"
#include <cstdint>
#include <cstddef>

extern "C" rustCudaError_t cuda_pool_available_memory(size_t* available);

extern "C" rustCudaError_t cuda_device_get_default_mem_pool(cudaMemPool_t* memPool, int32_t device);
extern "C" rustCudaError_t cuda_device_get_mem_pool(cudaMemPool_t* memPool, int32_t device);
extern "C" rustCudaError_t
cuda_mem_pool_set_release_threshold(cudaMemPool_t memPool, uint64_t threshold);
