#include <cstdint>
#include "algebra/algebra.cuh"

#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"

template <typename U, typename T>
__global__ void addKernel(U* a, T* b, U* c, size_t n) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < n; i += blockDim.x * gridDim.x) {
        c[i] = a[i] + b[i];
    }
}

// Bandwidth test kernel: reads `read_count` u32 elements and writes `write_count` u32 elements.
// Each write-thread accumulates (read_count / write_count) input elements via strided access,
// ensuring every input element is read and the compiler cannot elide any loads.
__global__ void bandwidthTestKernel(
    const uint32_t* input,
    uint32_t* output,
    size_t read_count,
    size_t write_count) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < write_count;
         i += blockDim.x * gridDim.x) {
        uint32_t acc = 0;
        for (size_t j = i; j < read_count; j += write_count) {
            acc += input[j];
        }
        output[i] = acc;
    }
}

template <typename T>
__global__ void addAssignKernel(T* a, T b, size_t n) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < n; i += blockDim.x * gridDim.x) {
        a[i] += b;
    }
}

extern "C" void* bandwidth_test_kernel() { return (void*)bandwidthTestKernel; }

extern "C" void* addKernelu32Ptr() { return (void*)addKernel<uint32_t, uint32_t>; }

extern "C" void* add_koala_bear_kernel() { return (void*)addKernel<kb31_t, kb31_t>; }

extern "C" void* add_koala_bear_ext_ext_kernel() {
    return (void*)addKernel<kb31_extension_t, kb31_extension_t>;
}

extern "C" void* add_koala_bear_base_ext_kernel() {
    return (void*)addKernel<kb31_extension_t, kb31_t>;
}

extern "C" void* add_assign_koala_bear_kernel() { return (void*)addAssignKernel<kb31_t>; }

extern "C" void* add_assign_koala_bear_ext_kernel() {
    return (void*)addAssignKernel<kb31_extension_t>;
}
