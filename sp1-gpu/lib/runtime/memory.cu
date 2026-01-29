#include <cuda_runtime.h>

#include "runtime/exception.cuh"
#include <cstdint>

extern "C" rustCudaError_t cuda_malloc(void** devPtr, size_t size) {
    CUDA_OK(cudaMalloc(devPtr, size));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_malloc_host(void** devPtr, size_t size) {
    CUDA_OK(cudaMallocHost(devPtr, size));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_host_register(void* hostPtr, size_t size) {
    CUDA_OK(cudaHostRegister(hostPtr, size, cudaHostRegisterDefault));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_free(void* devPtr) {
    CUDA_OK(cudaFree(devPtr));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_free_host(void* devPtr) {
    CUDA_OK(cudaFreeHost(devPtr));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_host_unregister(void* hostPtr) {
    CUDA_OK(cudaHostUnregister(hostPtr));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_mem_get_info(size_t* free, size_t* total) {
    CUDA_OK(cudaMemGetInfo(free, total));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_mem_copy_host_to_device(void* dst, const void* src, size_t count) {
    CUDA_OK(cudaMemcpy(dst, src, count, cudaMemcpyHostToDevice));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t cuda_mem_copy_device_to_host(void* dst, const void* src, size_t count) {
    CUDA_OK(cudaMemcpy(dst, src, count, cudaMemcpyDeviceToHost));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
cuda_mem_copy_device_to_device(void* dst, const void* src, size_t count) {
    CUDA_OK(cudaMemcpy(dst, src, count, cudaMemcpyDeviceToDevice));
    return CUDA_SUCCESS_CSL;
}
