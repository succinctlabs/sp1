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