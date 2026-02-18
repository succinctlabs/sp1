// CUDA runtime bindings.

#include <cuda.h>
#include <nvtx3/nvToolsExt.h>
#include <cuda_runtime.h>

#include "runtime/exception.cuh"

// Create an nvtx domain.

extern "C" nvtxDomainHandle_t nvtxDomainCreateARust(char* name) { return nvtxDomainCreateA(name); }

// Destroy an nvtx domain.

extern "C" void nvtxDomainDestroyARust(nvtxDomainHandle_t domain) { nvtxDomainDestroy(domain); }

// Create a global nvtx range.

extern "C" uint64_t nvtx_range_start(char* message) { return nvtxRangeStart(message); }

// Destroy a global nvtx range.

extern "C" void nvtx_range_end(uint64_t id) { nvtxRangeEnd(id); }

// Sync device

extern "C" rustCudaError_t cuda_device_synchronize() {
    CUDA_OK(cudaDeviceSynchronize());
    return CUDA_SUCCESS_CSL;
}

// Cuda events.

extern "C" rustCudaError_t cuda_event_create(cudaEvent_t* event) {
    CUDA_OK(cudaEventCreateWithFlags(event, cudaEventDisableTiming));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_event_destroy(cudaEvent_t event) {
    CUDA_OK(cudaEventDestroy(event));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_event_record(cudaEvent_t event, cudaStream_t stream) {
    CUDA_OK(cudaEventRecord(event, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_event_synchronize(cudaEvent_t event) {
    CUDA_OK(cudaEventSynchronize(event));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_event_elapsed_time(float* ms, cudaEvent_t start, cudaEvent_t end) {
    CUDA_OK(cudaEventElapsedTime(ms, start, end));
    return CUDA_SUCCESS_CSL;
}

// Cuda streams.

extern "C" const cudaStream_t DEFAULT_STREAM = cudaStreamDefault;

extern "C" rustCudaError_t cuda_stream_create(cudaStream_t* stream) {
    CUDA_OK(cudaStreamCreateWithFlags(stream, cudaStreamNonBlocking));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_stream_destroy(cudaStream_t stream) {
    CUDA_OK(cudaStreamDestroy(stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_stream_synchronize(cudaStream_t stream) {
    CUDA_OK(cudaStreamSynchronize(stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_stream_wait_event(cudaStream_t stream, cudaEvent_t event) {
    CUDA_OK(cudaStreamWaitEvent(stream, event));
    return CUDA_SUCCESS_CSL;
}

// Async memory operations.

extern "C" rustCudaError_t cuda_malloc_async(void** devPtr, size_t size, cudaStream_t stream) {
    CUDA_OK(cudaMallocAsync(devPtr, size, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_free_async(void* devPtr, cudaStream_t stream) {
    CUDA_OK(cudaFreeAsync(devPtr, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_mem_set_async(void* dst, uint8_t value, size_t count, cudaStream_t stream) {
    CUDA_OK(cudaMemsetAsync(dst, value, count, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_mem_set(void* dst, uint8_t value, size_t count) {
    CUDA_OK(cudaMemset(dst, value, count));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_mem_copy_device_to_device_async(
    void* dst,
    const void* src,
    size_t count,
    cudaStream_t stream) {
    CUDA_OK(cudaMemcpyAsync(dst, src, count, cudaMemcpyDeviceToDevice, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_mem_copy_host_to_device_async(void* dst, const void* src, size_t count, cudaStream_t stream) {
    CUDA_OK(cudaMemcpyAsync(dst, src, count, cudaMemcpyHostToDevice, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_mem_copy_device_to_host_async(void* dst, const void* src, size_t count, cudaStream_t stream) {
    CUDA_OK(cudaMemcpyAsync(dst, src, count, cudaMemcpyDeviceToHost, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_mem_copy_host_to_host_async(void* dst, const void* src, size_t count, cudaStream_t stream) {
    CUDA_OK(cudaMemcpyAsync(dst, src, count, cudaMemcpyHostToHost, stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_stream_query(cudaStream_t stream) {
    CUDA_OK(cudaStreamQuery(stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_event_query(cudaEvent_t event) {
    CUDA_OK(cudaEventQuery(event));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_launch_host_function(cudaStream_t stream, void (*fn)(void*), void* data) {
    CUDA_OK(cudaLaunchHostFunc(stream, fn, data));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_launch_kernel(
    void* kernel,
    dim3 grid,
    dim3 block,
    void** args,
    size_t shared_mem,
    cudaStream_t stream) {
    CUDA_OK(cudaLaunchKernel(kernel, grid, block, args, shared_mem, stream));
    return CUDA_SUCCESS_CSL;
}
