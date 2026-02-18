#pragma once

#include "runtime/exception.cuh"

extern "C" rustCudaError_t
populate_restrict_eq_host(const void* src, size_t len, cudaStream_t stream);

extern "C" rustCudaError_t
populate_restrict_eq_device(const void* src, size_t len, cudaStream_t stream);

extern "C" void* round_kernel_1_32_2_2_false();
extern "C" void* round_kernel_2_32_2_2_true();
extern "C" void* round_kernel_2_32_2_2_false();
extern "C" void* round_kernel_4_32_2_2_true();
extern "C" void* round_kernel_4_32_2_2_false();
extern "C" void* round_kernel_8_32_2_2_true();
extern "C" void* round_kernel_8_32_2_2_false();

// FIX_TILE=64 variants
extern "C" void* round_kernel_1_64_2_2_false();
extern "C" void* round_kernel_1_64_4_8_false();
extern "C" void* round_kernel_2_64_2_2_true();
extern "C" void* round_kernel_2_64_2_2_false();
extern "C" void* round_kernel_4_64_2_2_true();
extern "C" void* round_kernel_4_64_2_2_false();
extern "C" void* round_kernel_4_64_4_8_true();
extern "C" void* round_kernel_4_64_4_8_false();

extern "C" void* round_kernel_8_64_2_2_true();
extern "C" void* round_kernel_8_64_2_2_false();

extern "C" void* round_kernel_1_128_4_8_false();