#include "config.cuh"
#include "sum_and_reduce/sum.cuh"

/// A generic sum kernel that can be used for any type that implements the `+`
/// operator.
template <typename F>
__global__ void sumKernel(F* A, F* B, F* C, size_t N) {
    // The size bounds are being checked using a "grid stride loop" instead of a simple "if"
    // statement in order to facilitate the freedom to support different workloads per thread.
    // making a non-zero stride causes less blocks to be launched, which could result in a faster
    // total execution time. For more information, see:
    // https://developer.nvidia.com/blog/cuda-pro-tip-write-flexible-kernels-grid-stride-loops/
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < N; i += blockDim.x * gridDim.x) {
        // Sum the elements in A and B and store the result in C
        C[i] = A[i] + B[i];
    }
}

// A pointer to the sum kernel for uint32_t.
extern "C" void* sum_kernel_u32() { return (void*)sumKernel<uint32_t>; }

// A pointer to the sum kernel for felt_t.
extern "C" void* sum_kernel_felt() { return (void*)sumKernel<felt_t>; }

// A pointer to the sum kernel for ext_t.
extern "C" void* sum_kernel_ext() { return (void*)sumKernel<ext_t>; }