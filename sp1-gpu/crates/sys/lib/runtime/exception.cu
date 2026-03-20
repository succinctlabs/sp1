#include "runtime/exception.cuh"

#ifdef __HIPCC__
extern "C" const rustCudaError_t CUDA_SUCCESS_CSL =
    rustCudaError_t{.message = hipGetErrorString(hipSuccess)};

extern "C" const rustCudaError_t CUDA_OUT_OF_MEMORY =
    rustCudaError_t{.message = hipGetErrorString(hipErrorOutOfMemory)};

extern "C" const rustCudaError_t CUDA_ERROR_NOT_READY_SLOP =
    rustCudaError_t{.message = hipGetErrorString(hipErrorNotReady)};
#else
extern "C" const rustCudaError_t CUDA_SUCCESS_CSL =
    rustCudaError_t{.message = cudaGetErrorString(cudaSuccess)};

extern "C" const rustCudaError_t CUDA_OUT_OF_MEMORY =
    rustCudaError_t{.message = cudaGetErrorString(cudaErrorMemoryAllocation)};

extern "C" const rustCudaError_t CUDA_ERROR_NOT_READY_SLOP =
    rustCudaError_t{.message = cudaGetErrorString(cudaErrorNotReady)};
#endif
