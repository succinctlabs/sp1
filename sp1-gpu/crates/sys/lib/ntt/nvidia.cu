#include <ff/koala_bear.hpp>

#include "ntt/nvidia.cuh"

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
