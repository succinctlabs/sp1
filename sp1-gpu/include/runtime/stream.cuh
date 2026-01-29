#pragma once

#include "runtime/exception.cuh"
#include <nvtx3/nvToolsExt.h>

extern "C" rustCudaError_t cuda_device_synchronize();

extern "C" nvtxDomainHandle_t nvtxDomainCreateARust(char* name);

extern "C" void nvtxDomainDestroyARust(nvtxDomainHandle_t domain);

extern "C" uint64_t nvtx_range_start(char* message);

extern "C" void nvtx_range_end(uint64_t id);

extern "C" uint64_t nvtx_range_start(char* message);

// Cuda events.

extern "C" rustCudaError_t cuda_event_create(cudaEvent_t* event);

extern "C" rustCudaError_t cuda_event_destroy(cudaEvent_t event);

extern "C" rustCudaError_t cuda_event_record(cudaEvent_t event, cudaStream_t stream);

extern "C" rustCudaError_t cuda_event_synchronize(cudaEvent_t event);

extern "C" rustCudaError_t cuda_event_elapsed_time(float* ms, cudaEvent_t start, cudaEvent_t end);

// Cuda streams.

extern "C" const cudaStream_t DEFAULT_STREAM = cudaStreamDefault;

extern "C" rustCudaError_t cuda_stream_create(cudaStream_t* stream);

extern "C" rustCudaError_t cuda_stream_destroy(cudaStream_t stream);

extern "C" rustCudaError_t cuda_stream_synchronize(cudaStream_t stream);

extern "C" rustCudaError_t cuda_stream_wait_event(cudaStream_t stream, cudaEvent_t event);

// Async memory operations.

extern "C" rustCudaError_t cuda_malloc_async(void** devPtr, size_t size, cudaStream_t stream);

extern "C" rustCudaError_t cuda_free_async(void* devPtr, cudaStream_t stream);

extern "C" rustCudaError_t
cuda_mem_set_async(void* dst, uint8_t value, size_t count, cudaStream_t stream);

extern "C" rustCudaError_t cuda_mem_set(void* dst, uint8_t value, size_t count);

extern "C" rustCudaError_t
cuda_mem_copy_device_to_device_async(void* dst, const void* src, size_t count, cudaStream_t stream);

extern "C" rustCudaError_t
cuda_mem_copy_host_to_device_async(void* dst, const void* src, size_t count, cudaStream_t stream);

extern "C" rustCudaError_t
cuda_mem_copy_device_to_host_async(void* dst, const void* src, size_t count, cudaStream_t stream);

extern "C" rustCudaError_t
cuda_mem_copy_host_to_host_async(void* dst, const void* src, size_t count, cudaStream_t stream);

extern "C" rustCudaError_t cuda_stream_query(cudaStream_t stream);

extern "C" rustCudaError_t cuda_event_query(cudaEvent_t event);

extern "C" rustCudaError_t
cuda_launch_host_function(cudaStream_t stream, void (*fn)(void*), void* data);

extern "C" rustCudaError_t cuda_launch_kernel(
    void* kernel,
    dim3 grid,
    dim3 block,
    void** args,
    size_t shared_mem,
    cudaStream_t stream);
