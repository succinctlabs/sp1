#include "runtime/mem_pool.cuh"

extern "C" rustCudaError_t
cuda_device_get_default_mem_pool(cudaMemPool_t* memPool, int32_t device) {
    CUDA_OK(cudaDeviceGetDefaultMemPool(memPool, device));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_device_get_mem_pool(cudaMemPool_t* memPool, int32_t device) {
    CUDA_OK(cudaDeviceGetMemPool(memPool, device));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_mem_pool_set_release_threshold(cudaMemPool_t memPool, uint64_t threshold) {
    CUDA_OK(cudaMemPoolSetAttribute(memPool, cudaMemPoolAttrReleaseThreshold, &threshold));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_pool_available_memory(size_t* available) {
    int device;
    cudaMemPool_t pool;
    size_t free, total;
    uint64_t reserved, used;
    CUDA_OK(cudaGetDevice(&device));
    CUDA_OK(cudaDeviceGetMemPool(&pool, device));
    CUDA_OK(cudaMemGetInfo(&free, &total));
    CUDA_OK(cudaMemPoolGetAttribute(pool, cudaMemPoolAttrReservedMemCurrent, &reserved));
    CUDA_OK(cudaMemPoolGetAttribute(pool, cudaMemPoolAttrUsedMemCurrent, &used));
    *available = free + (reserved > used ? reserved - used : 0);
    return CUDA_SUCCESS_CSL;
}
