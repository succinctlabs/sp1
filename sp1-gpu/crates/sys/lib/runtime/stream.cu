// CUDA/HIP runtime bindings.

#include "runtime/exception.cuh"

#ifdef __HIPCC__
using cudaStream_t = hipStream_t;
using cudaEvent_t = hipEvent_t;
#define cudaDeviceSynchronize hipDeviceSynchronize
#define cudaEventCreateWithFlags hipEventCreateWithFlags
#define cudaEventDisableTiming hipEventDisableTiming
#define cudaEventDestroy hipEventDestroy
#define cudaEventRecord hipEventRecord
#define cudaEventSynchronize hipEventSynchronize
#define cudaEventElapsedTime hipEventElapsedTime
#define cudaEventQuery hipEventQuery
#define cudaStreamCreateWithFlags hipStreamCreateWithFlags
#define cudaStreamNonBlocking hipStreamNonBlocking
#define cudaStreamDefault hipStreamDefault
#define cudaStreamDestroy hipStreamDestroy
#define cudaStreamSynchronize hipStreamSynchronize
#define cudaStreamWaitEvent hipStreamWaitEvent
#define cudaStreamQuery hipStreamQuery
#define cudaMemcpyAsync hipMemcpyAsync
#define cudaMemsetAsync hipMemsetAsync
#define cudaMemcpyDeviceToDevice hipMemcpyDeviceToDevice
#define cudaMemcpyHostToDevice hipMemcpyHostToDevice
#define cudaMemcpyDeviceToHost hipMemcpyDeviceToHost
#define cudaMemcpyHostToHost hipMemcpyHostToHost
#define cudaMemset hipMemset
#define cudaLaunchKernel hipLaunchKernel
#define cudaLaunchHostFunc hipLaunchHostFunc
using cudaHostFn_t = hipHostFn_t;
#else
#include <cuda.h>
#endif

#if __has_include(<nvtx3/nvToolsExt.h>)
#include <nvtx3/nvToolsExt.h>
#define HAS_NVTX 1
#else
typedef void* nvtxDomainHandle_t;
#define HAS_NVTX 0
#endif

#ifdef __HIPCC__
// ROCm bug: hipMallocAsync/hipFreeAsync leak memory.
// Use a caching allocator over synchronous hipMalloc/hipFree to avoid the
// overhead of calling the driver for every allocation.
#include <unordered_map>
#include <vector>
#include <mutex>

static std::mutex g_alloc_mutex;
static std::unordered_map<size_t, std::vector<void*>> g_free_pool;
static std::unordered_map<void*, size_t> g_alloc_sizes;
static size_t g_cached_bytes = 0;
static constexpr size_t MAX_CACHED_BYTES = 2ULL * 1024 * 1024 * 1024; // 2 GB limit

static hipError_t cachedHipMalloc(void** p, size_t s, hipStream_t) {
    if (s == 0) { *p = nullptr; return hipSuccess; }
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    auto it = g_free_pool.find(s);
    if (it != g_free_pool.end() && !it->second.empty()) {
        *p = it->second.back();
        it->second.pop_back();
        g_cached_bytes -= s;
        return hipSuccess;
    }
    hipError_t err = hipMalloc(p, s);
    if (err != hipSuccess) {
        // OOM: synchronize GPU work, evict all cached entries, and retry
        hipDeviceSynchronize();
        for (auto& [sz, ptrs] : g_free_pool) {
            for (auto ptr : ptrs) {
                hipFree(ptr);
                g_alloc_sizes.erase(ptr);
            }
            g_cached_bytes -= sz * ptrs.size();
            ptrs.clear();
        }
        g_free_pool.clear();
        g_cached_bytes = 0;
        err = hipMalloc(p, s);
    }
    if (err == hipSuccess) {
        g_alloc_sizes[*p] = s;
    }
    return err;
}

static hipError_t cachedHipFree(void* p, hipStream_t) {
    if (p == nullptr) return hipSuccess;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    auto it = g_alloc_sizes.find(p);
    if (it != g_alloc_sizes.end()) {
        size_t s = it->second;
        if (g_cached_bytes + s <= MAX_CACHED_BYTES) {
            g_free_pool[s].push_back(p);
            g_cached_bytes += s;
            return hipSuccess;
        }
        g_alloc_sizes.erase(it);
    }
    return hipFree(p);
}

#define cudaMallocAsync cachedHipMalloc
#define cudaFreeAsync cachedHipFree
#endif // __HIPCC__

// Create an nvtx domain.

extern "C" nvtxDomainHandle_t nvtxDomainCreateARust(char* name) {
#if HAS_NVTX
    return nvtxDomainCreateA(name);
#else
    return nullptr;
#endif
}

// Destroy an nvtx domain.

extern "C" void nvtxDomainDestroyARust(nvtxDomainHandle_t domain) {
#if HAS_NVTX
    nvtxDomainDestroy(domain);
#endif
}

// Create a global nvtx range.

extern "C" uint64_t nvtx_range_start(char* message) {
#if HAS_NVTX
    return nvtxRangeStart(message);
#else
    return 0;
#endif
}

// Destroy a global nvtx range.

extern "C" void nvtx_range_end(uint64_t id) {
#if HAS_NVTX
    nvtxRangeEnd(id);
#endif
}

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
