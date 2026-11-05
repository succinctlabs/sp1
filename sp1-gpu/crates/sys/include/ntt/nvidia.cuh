#pragma once

#include <cuda_runtime.h>
#include <ntt.hpp>

#include <cstdint>
#include <map>
#include <mutex>

namespace nvidia_ntt {

constexpr uint32_t PRIME = cupqc::KoalaBear;
constexpr uint32_t BLOCK_SIZE = 128;

template <uint32_t N, cupqc::nttDirection D>
using StandardNtt = decltype(
    cupqc::Algorithm<cupqc::algorithm::NTT>() + cupqc::Direction<D>() +
    cupqc::Precision<uint32_t>() + cupqc::Size<N>() + cupqc::Block() +
    cupqc::BlockDim<BLOCK_SIZE>());

template <uint32_t N, uint32_t M, cupqc::nttDirection D>
using StagedNtt = decltype(
    cupqc::Algorithm<cupqc::algorithm::NTT>() + cupqc::Direction<D>() +
    cupqc::Precision<uint32_t>() + cupqc::Size<N>() + cupqc::SubSize<M>() +
    cupqc::Block() + cupqc::BlockDim<BLOCK_SIZE>());

constexpr uint32_t primitive_root(uint32_t log_size) {
    uint64_t root = cupqc::KoalaBear_primitive_root_24;
    for (uint32_t log = 24; log > log_size; --log) {
        root = root * root % PRIME;
    }
    return static_cast<uint32_t>(root);
}

inline uint32_t mod_pow(uint64_t base, uint32_t exponent) {
    uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = result * base % PRIME;
        }
        base = base * base % PRIME;
        exponent >>= 1;
    }
    return static_cast<uint32_t>(result);
}

template <class Ntt>
__global__ void make_twiddles(uint32_t* twiddles, uint32_t root) {
    Ntt().make_twiddles(twiddles, PRIME, root);
}

template <class Ntt>
__global__ void twiddles_to_montgomery(uint32_t* twiddles) {
    Ntt().transform_twiddles_to_mont(twiddles, PRIME);
}

struct TwiddleCache {
    uint32_t* forward = nullptr;
    uint32_t* inverse = nullptr;
    bool initialized = false;
};

template <uint32_t N, class ForwardNtt, class InverseNtt>
cudaError_t get_twiddles(
    uint32_t*& forward,
    uint32_t*& inverse,
    const cudaStream_t stream) {
    static std::mutex mutex;
    static std::map<int, TwiddleCache> caches;
    int device;
    cudaError_t error = cudaGetDevice(&device);
    if (error != cudaSuccess) {
        return error;
    }
    std::lock_guard lock(mutex);
    TwiddleCache& cache = caches[device];

    if (!cache.initialized) {
        error = cudaMalloc(reinterpret_cast<void**>(&cache.forward), N * sizeof(uint32_t));
        if (error == cudaSuccess) {
            error = cudaMalloc(reinterpret_cast<void**>(&cache.inverse), N * sizeof(uint32_t));
        }

        constexpr uint32_t log_size = __builtin_ctz(N);
        const uint32_t root = primitive_root(log_size);
        if (error == cudaSuccess) {
            make_twiddles<ForwardNtt><<<1, 1, 0, stream>>>(cache.forward, root);
            error = cudaGetLastError();
        }
        if (error == cudaSuccess) {
            make_twiddles<InverseNtt><<<1, 1, 0, stream>>>(
                cache.inverse, mod_pow(root, PRIME - 2));
            error = cudaGetLastError();
        }
        if (error == cudaSuccess) {
            twiddles_to_montgomery<ForwardNtt><<<1, ForwardNtt::BlockDim, 0, stream>>>(
                cache.forward);
            error = cudaGetLastError();
        }
        if (error == cudaSuccess) {
            twiddles_to_montgomery<InverseNtt><<<1, InverseNtt::BlockDim, 0, stream>>>(
                cache.inverse);
            error = cudaGetLastError();
        }
        if (error == cudaSuccess) {
            error = cudaStreamSynchronize(stream);
        }
        if (error != cudaSuccess) {
            cudaFree(cache.forward);
            cudaFree(cache.inverse);
            cache.forward = nullptr;
            cache.inverse = nullptr;
            return error;
        }
        cache.initialized = true;
    }

    forward = cache.forward;
    inverse = cache.inverse;
    return cudaSuccess;
}

template <class Ntt, bool INVERSE>
__global__ void standard_ntt(
    uint32_t* data,
    const uint32_t stride,
    const uint32_t* twiddles,
    const uint32_t n_inv) {
    extern __shared__ uint32_t shared[];
    uint32_t* polynomial = data + blockIdx.x * stride;
    Ntt ntt;
    ntt.load(shared, polynomial);
    __syncthreads();
    if constexpr (INVERSE) {
        ntt.execute(shared, twiddles, PRIME, n_inv);
    } else {
        ntt.execute(shared, twiddles, PRIME);
    }
    __syncthreads();
    ntt.store(shared, polynomial);
}

template <uint32_t N, uint32_t M, class Ntt, bool INVERSE>
__global__ void staged_ntt_first(
    uint32_t* data,
    const uint32_t stride,
    const uint32_t* twiddles) {
    data += blockIdx.y * stride;
    extern __shared__ uint32_t shared[];
    Ntt ntt;
    ntt.stage_1_load(shared, data, blockIdx.x);
    __syncthreads();
    ntt.stage_1_execute(shared, twiddles, PRIME);
    __syncthreads();
    ntt.stage_1_store(shared, data, blockIdx.x);
}

__device__ __forceinline__ fr_t lde_root(uint32_t power, const fr_t* roots) {
    if (power == 0) {
        return fr_t::one();
    }

    constexpr uint32_t window_bits = 5;
    constexpr uint32_t window_size = 1U << window_bits;
    uint32_t window = 0;
    while ((power & (window_size - 1)) == 0) {
        power >>= window_bits;
        ++window;
    }

    fr_t root = roots[window * window_size + (power & (window_size - 1))];
    while (power >>= window_bits) {
        ++window;
        root *= roots[window * window_size + (power & (window_size - 1))];
    }
    return root;
}

template <uint32_t N, uint32_t M, class Ntt>
__global__ void staged_ntt_first_coset(
    uint32_t* output,
    const fr_t* input,
    const uint32_t input_size,
    const fr_t* gen_powers,
    const fr_t shift,
    const bool perform_shift,
    const uint32_t* twiddles) {
    output += blockIdx.y * N;
    input += blockIdx.y * input_size;
    extern __shared__ uint32_t shared[];
    constexpr uint32_t chunk_size = N / M;

    // cuPQC uses this strided input layout for forward stage one.
    for (uint32_t offset = threadIdx.x; offset < chunk_size; offset += blockDim.x) {
        const uint32_t index = blockIdx.x + M * offset;
        fr_t value = fr_t::zero();
        if (index < input_size) {
            value = input[index];
            if (perform_shift) {
                value = value * lde_root(index, gen_powers) * (shift^index);
            }
        }
        shared[offset] = value.val;
    }

    __syncthreads();
    Ntt ntt;
    ntt.stage_1_execute(shared, twiddles, PRIME);
    __syncthreads();
    ntt.stage_1_store(shared, output, blockIdx.x);
}

template <uint32_t N, uint32_t M, class Ntt, bool INVERSE>
__global__ void staged_ntt_second(
    uint32_t* data,
    const uint32_t stride,
    const uint32_t* twiddles,
    const uint32_t n_inv) {
    data += blockIdx.y * stride;
    extern __shared__ uint32_t shared[];
    Ntt ntt;
    ntt.stage_2_load(shared, data, blockIdx.x);
    __syncthreads();
    if constexpr (INVERSE) {
        ntt.stage_2_execute(shared, twiddles, PRIME, n_inv);
    } else {
        ntt.stage_2_execute(shared, twiddles, PRIME);
    }
    __syncthreads();
    ntt.stage_2_store(shared, data, blockIdx.x);
}

template <uint32_t N>
cudaError_t launch_standard(
    uint32_t* data,
    const uint32_t polynomial_count,
    const uint32_t stride,
    const bool inverse,
    const cudaStream_t stream) {
    using ForwardNtt = StandardNtt<N, cupqc::nttDirection::FORWARD>;
    using InverseNtt = StandardNtt<N, cupqc::nttDirection::INVERSE>;
    uint32_t* forward_twiddles;
    uint32_t* inverse_twiddles;
    cudaError_t error = get_twiddles<N, ForwardNtt, InverseNtt>(
        forward_twiddles, inverse_twiddles, stream);
    if (error != cudaSuccess) {
        return error;
    }
    if (polynomial_count == 0) {
        return cudaSuccess;
    }

    constexpr size_t shared_memory = cupqc::ntt_shared_workspace_size<N, uint32_t>();
    const uint32_t n_inv = cupqc::n_inv<N>(PRIME);
    if (inverse) {
        standard_ntt<InverseNtt, true><<<polynomial_count, BLOCK_SIZE, shared_memory, stream>>>(
            data, stride, inverse_twiddles, n_inv);
    } else {
        standard_ntt<ForwardNtt, false><<<polynomial_count, BLOCK_SIZE, shared_memory, stream>>>(
            data, stride, forward_twiddles, n_inv);
    }
    return cudaGetLastError();
}

__global__ void prepare_size_512(
    const uint32_t* data,
    uint32_t* workspace,
    const uint32_t stride,
    const bool inverse) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t polynomial = index / 1024;
    const uint32_t offset = index % 1024;
    if (inverse) {
        workspace[index] = (offset & 1) == 0 ? data[polynomial * stride + offset / 2] : 0;
    } else {
        workspace[index] = offset < 512 ? data[polynomial * stride + offset] : 0;
    }
}

__global__ void finish_size_512(
    uint32_t* data,
    const uint32_t* workspace,
    const uint32_t stride,
    const bool inverse) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t polynomial = index / 512;
    const uint32_t offset = index % 512;
    uint32_t value = workspace[polynomial * 1024 + (inverse ? 2 * offset : offset)];
    if (inverse) {
        value = value >= PRIME - value ? value - (PRIME - value) : value + value;
    }
    data[polynomial * stride + offset] = value;
}

inline cudaError_t launch_size_512(
    uint32_t* data,
    const uint32_t polynomial_count,
    const uint32_t stride,
    const bool inverse,
    const cudaStream_t stream) {
    if (polynomial_count == 0) {
        return launch_standard<1024>(nullptr, 0, 0, inverse, stream);
    }
    uint32_t* workspace = nullptr;
    cudaError_t error = cudaMallocAsync(
        reinterpret_cast<void**>(&workspace), polynomial_count * 1024 * sizeof(uint32_t), stream);
    constexpr uint32_t threads = 256;
    if (error == cudaSuccess) {
        prepare_size_512<<<polynomial_count * 4, threads, 0, stream>>>(
            data, workspace, stride, inverse);
        error = cudaGetLastError();
    }
    if (error == cudaSuccess) {
        error = launch_standard<1024>(workspace, polynomial_count, 1024, inverse, stream);
    }
    if (error == cudaSuccess) {
        finish_size_512<<<polynomial_count * 2, threads, 0, stream>>>(
            data, workspace, stride, inverse);
        error = cudaGetLastError();
    }
    const cudaError_t free_error =
        workspace == nullptr ? cudaSuccess : cudaFreeAsync(workspace, stream);
    return error == cudaSuccess ? free_error : error;
}

template <uint32_t N, uint32_t M>
cudaError_t launch_staged(
    uint32_t* data,
    const uint32_t polynomial_count,
    const uint32_t stride,
    const bool inverse,
    const cudaStream_t stream) {
    using ForwardNtt = StagedNtt<N, M, cupqc::nttDirection::FORWARD>;
    using InverseNtt = StagedNtt<N, M, cupqc::nttDirection::INVERSE>;
    uint32_t* forward_twiddles;
    uint32_t* inverse_twiddles;
    cudaError_t error = get_twiddles<N, ForwardNtt, InverseNtt>(
        forward_twiddles, inverse_twiddles, stream);
    if (error != cudaSuccess) {
        return error;
    }
    if (polynomial_count == 0) {
        return cudaSuccess;
    }

    const uint32_t n_inv = cupqc::n_inv<N>(PRIME);
    if (inverse) {
        constexpr size_t first_shared =
            cupqc::inv_stage_1_ntt_shared_workspace_size<N, M, uint32_t>();
        constexpr size_t second_shared =
            cupqc::inv_stage_2_ntt_shared_workspace_size<N, M, uint32_t>();
        staged_ntt_first<N, M, InverseNtt, true>
            <<<dim3(N / M, polynomial_count), BLOCK_SIZE, first_shared, stream>>>(
                data, stride, inverse_twiddles);
        error = cudaGetLastError();
        if (error == cudaSuccess) {
            staged_ntt_second<N, M, InverseNtt, true>
                <<<dim3(M, polynomial_count), BLOCK_SIZE, second_shared, stream>>>(
                    data, stride, inverse_twiddles, n_inv);
            error = cudaGetLastError();
        }
    } else {
        constexpr size_t first_shared =
            cupqc::fwd_stage_1_ntt_shared_workspace_size<N, M, uint32_t>();
        constexpr size_t second_shared =
            cupqc::fwd_stage_2_ntt_shared_workspace_size<N, M, uint32_t>();
        staged_ntt_first<N, M, ForwardNtt, false>
            <<<dim3(M, polynomial_count), BLOCK_SIZE, first_shared, stream>>>(
                data, stride, forward_twiddles);
        error = cudaGetLastError();
        if (error == cudaSuccess) {
            staged_ntt_second<N, M, ForwardNtt, false>
                <<<dim3(N / M, polynomial_count), BLOCK_SIZE, second_shared, stream>>>(
                    data, stride, forward_twiddles, n_inv);
            error = cudaGetLastError();
        }
    }
    return error;
}

template <uint32_t N, uint32_t M>
cudaError_t launch_staged_coset(
    uint32_t* output,
    const uint32_t polynomial_count,
    const fr_t* input,
    const uint32_t input_size,
    const fr_t* gen_powers,
    const fr_t shift,
    const bool perform_shift,
    const cudaStream_t stream) {
    using ForwardNtt = StagedNtt<N, M, cupqc::nttDirection::FORWARD>;
    using InverseNtt = StagedNtt<N, M, cupqc::nttDirection::INVERSE>;
    uint32_t* forward_twiddles;
    uint32_t* inverse_twiddles;
    cudaError_t error = get_twiddles<N, ForwardNtt, InverseNtt>(
        forward_twiddles, inverse_twiddles, stream);
    if (error != cudaSuccess || polynomial_count == 0) {
        return error;
    }

    constexpr size_t first_shared =
        cupqc::fwd_stage_1_ntt_shared_workspace_size<N, M, uint32_t>();
    constexpr size_t second_shared =
        cupqc::fwd_stage_2_ntt_shared_workspace_size<N, M, uint32_t>();
    staged_ntt_first_coset<N, M, ForwardNtt>
        <<<dim3(M, polynomial_count), BLOCK_SIZE, first_shared, stream>>>(
            output, input, input_size, gen_powers, shift, perform_shift,
            forward_twiddles);
    error = cudaGetLastError();
    if (error == cudaSuccess) {
        staged_ntt_second<N, M, ForwardNtt, false>
            <<<dim3(N / M, polynomial_count), BLOCK_SIZE, second_shared, stream>>>(
                output, N, forward_twiddles, cupqc::n_inv<N>(PRIME));
        error = cudaGetLastError();
    }
    return error;
}

__global__ void size_two_ntt(fr_t* data, const uint32_t stride, const bool inverse) {
    fr_t* polynomial = data + blockIdx.x * stride;
    const fr_t first = polynomial[0];
    const fr_t second = polynomial[1];
    polynomial[0] = first + second;
    polynomial[1] = first - second;
    if (inverse) {
        const fr_t inverse_two = fr_t::from_canonical_u32((PRIME + 1) / 2);
        polynomial[0] *= inverse_two;
        polynomial[1] *= inverse_two;
    }
}

inline cudaError_t batch_ntt(
    fr_t* data,
    const uint32_t log_size,
    const uint32_t polynomial_count,
    const uint32_t stride,
    const bool inverse,
    const cudaStream_t stream) {
    if (log_size == 0) {
        return cudaSuccess;
    }
    if (log_size == 1) {
        if (polynomial_count == 0) {
            return cudaSuccess;
        }
        size_two_ntt<<<polynomial_count, 1, 0, stream>>>(data, stride, inverse);
        return cudaGetLastError();
    }

    uint32_t* values = reinterpret_cast<uint32_t*>(data);
#define STANDARD_CASE(LOG)                                                                    \
    case LOG:                                                                                 \
        return launch_standard<(1U << LOG)>(values, polynomial_count, stride, inverse, stream)
#define STAGED_CASE(LOG, SUB_SIZE)                                                             \
    case LOG:                                                                                 \
        return launch_staged<(1U << LOG), SUB_SIZE>(                                           \
            values, polynomial_count, stride, inverse, stream)
    switch (log_size) {
        STANDARD_CASE(2);
        STANDARD_CASE(3);
        STANDARD_CASE(4);
        STANDARD_CASE(5);
        STANDARD_CASE(6);
        STANDARD_CASE(7);
        STANDARD_CASE(8);
        // cuPQC 0.6.0 omits its size-512 twiddle symbols. A size-1024 NTT gives
        // the same transform at its even evaluation points.
        case 9:
            return launch_size_512(values, polynomial_count, stride, inverse, stream);
        STANDARD_CASE(10);
        STANDARD_CASE(11);
        STANDARD_CASE(12);
        STANDARD_CASE(13);
        STAGED_CASE(14, 256);
        STAGED_CASE(15, 256);
        STAGED_CASE(16, 256);
        STAGED_CASE(17, 512);
        STAGED_CASE(18, 512);
        STAGED_CASE(19, 1024);
        STAGED_CASE(20, 1024);
        STAGED_CASE(21, 2048);
        STAGED_CASE(22, 2048);
        STAGED_CASE(23, 1024);
        STAGED_CASE(24, 4096);
        default:
            return cudaErrorInvalidValue;
    }
#undef STAGED_CASE
#undef STANDARD_CASE
}

inline cudaError_t batch_coset_ntt(
    fr_t* data,
    const fr_t* input,
    const uint32_t log_size,
    const uint32_t log_blowup,
    const uint32_t polynomial_count,
    const fr_t* gen_powers,
    const fr_t shift,
    const bool perform_shift,
    const cudaStream_t stream) {
    const uint32_t stride = 1U << log_size;
    const uint32_t input_size = stride >> log_blowup;
#define STAGED_COSET_CASE(LOG, SUB_SIZE)                                                       \
    case LOG:                                                                                 \
        return launch_staged_coset<(1U << LOG), SUB_SIZE>(                                    \
            reinterpret_cast<uint32_t*>(data), polynomial_count, input, input_size,            \
            gen_powers, shift, perform_shift, stream)
    switch (log_size) {
        STAGED_COSET_CASE(14, 256);
        STAGED_COSET_CASE(15, 256);
        STAGED_COSET_CASE(16, 256);
        STAGED_COSET_CASE(17, 512);
        STAGED_COSET_CASE(18, 512);
        STAGED_COSET_CASE(19, 1024);
        STAGED_COSET_CASE(20, 1024);
        STAGED_COSET_CASE(21, 2048);
        STAGED_COSET_CASE(22, 2048);
        STAGED_COSET_CASE(23, 1024);
        STAGED_COSET_CASE(24, 4096);
        default:
            return cudaErrorInvalidValue;
    }
#undef STAGED_COSET_CASE
}

}  // namespace nvidia_ntt
