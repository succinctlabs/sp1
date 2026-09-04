#include <ff/koala_bear.hpp>

#include "ntt/nvidia.cuh"

cudaError_t nvidia_ntt_init(uint32_t max_log_size, cudaStream_t stream) {
    if (max_log_size > 24) {
        return cudaErrorInvalidValue;
    }
    for (uint32_t log_size = 2; log_size <= max_log_size; ++log_size) {
        cudaError_t error = nvidia_ntt::batch_ntt(nullptr, log_size, 0, 0, false, stream);
        if (error != cudaSuccess) {
            return error;
        }
    }
    return cudaSuccess;
}

cudaError_t nvidia_ntt_batch(
    fr_t* data,
    uint32_t log_size,
    uint32_t polynomial_count,
    uint32_t stride,
    bool inverse,
    cudaStream_t stream) {
    return nvidia_ntt::batch_ntt(
        data, log_size, polynomial_count, stride, inverse, stream);
}

cudaError_t nvidia_ntt_batch_coset(
    fr_t* data,
    const fr_t* input,
    uint32_t log_size,
    uint32_t log_blowup,
    uint32_t polynomial_count,
    const fr_t* gen_powers,
    fr_t shift,
    bool perform_shift,
    cudaStream_t stream) {
    return nvidia_ntt::batch_coset_ntt(
        data,
        input,
        log_size,
        log_blowup,
        polynomial_count,
        gen_powers,
        shift,
        perform_shift,
        stream);
}
