#pragma once

#include "runtime/exception.cuh"

extern "C" rustCudaError_t cuda_malloc(void** devPtr, size_t size);

extern "C" rustCudaError_t cuda_malloc_host(void** devPtr, size_t size);

extern "C" rustCudaError_t cuda_host_register(void* hostPtr, size_t size);

extern "C" rustCudaError_t cuda_free(void* devPtr);

extern "C" rustCudaError_t cuda_free_host(void* devPtr);

extern "C" rustCudaError_t cuda_host_unregister(void* hostPtr);

extern "C" rustCudaError_t cuda_mem_get_info(size_t* free, size_t* total);

extern "C" rustCudaError_t cuda_mem_copy_host_to_device(void* dst, const void* src, size_t count);

extern "C" rustCudaError_t cuda_mem_copy_device_to_host(void* dst, const void* src, size_t count);

extern "C" rustCudaError_t cuda_mem_copy_device_to_device(void* dst, const void* src, size_t count);
