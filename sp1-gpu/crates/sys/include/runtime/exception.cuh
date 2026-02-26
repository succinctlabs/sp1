#pragma once

struct RustCudaError {
    const char* message;
};

typedef struct RustCudaError rustCudaError_t;

extern "C" const rustCudaError_t CUDA_SUCCESS_CSL;

extern "C" const rustCudaError_t CUDA_OUT_OF_MEMORY;

extern "C" const rustCudaError_t CUDA_ERROR_NOT_READY_SLOP;

#define CUDA_UNWRAP(expr)                                                                          \
    do {                                                                                           \
        cudaError_t code = expr;                                                                   \
        if (code != cudaSuccess) {                                                                 \
            std::stringstream ss;                                                                  \
            ss << __FILE__ << "(" << __LINE__ << ")";                                              \
            std::string file_and_line;                                                             \
            ss >> file_and_line;                                                                   \
            throw thrust::system_error(code, thrust::cuda_category(), file_and_line);              \
        }                                                                                          \
    } while (0)

#define CUDA_OK(expr)                                                                              \
    do {                                                                                           \
        cudaError_t code = expr;                                                                   \
        if (code != cudaSuccess) {                                                                 \
            return rustCudaError_t{.message = cudaGetErrorString(code)};                           \
        }                                                                                          \
    } while (0)
