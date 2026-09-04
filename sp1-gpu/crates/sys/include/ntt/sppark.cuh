
#include <cuda.h>

#if defined(FEATURE_BLS12_381)
#include <ff/bls12-381.hpp>
#elif defined(FEATURE_BLS12_377)
#include <ff/bls12-377.hpp>
#elif defined(FEATURE_PALLAS)
#include <ff/pasta.hpp>
#elif defined(FEATURE_VESTA)
#include <ff/pasta.hpp>
#elif defined(FEATURE_BN254)
#include <ff/alt_bn128.hpp>
#elif defined(FEATURE_GOLDILOCKS)
#include <ff/goldilocks.hpp>
#elif defined(FEATURE_KOALA_BEAR)
#include <ff/koala_bear.hpp>
#else
#error "no FEATURE"
#endif

#include <ntt/ntt.cuh>
#ifdef NVIDIA_NTT
cudaError_t nvidia_ntt_init(uint32_t max_log_size, cudaStream_t stream);
cudaError_t nvidia_ntt_batch(
    fr_t* data,
    uint32_t log_size,
    uint32_t polynomial_count,
    uint32_t stride,
    bool inverse,
    cudaStream_t stream);
cudaError_t nvidia_ntt_batch_coset(
    fr_t* data,
    const fr_t* input,
    uint32_t log_size,
    uint32_t log_blowup,
    uint32_t polynomial_count,
    const fr_t* gen_powers,
    fr_t shift,
    bool perform_shift,
    cudaStream_t stream);
#endif

#include "runtime/exception.cuh"

#ifndef __CUDA_ARCH__

#ifdef NVIDIA_NTT
static constexpr bool LDE_INPUT_BIT_REVERSED = false;
static constexpr auto LDE_FORWARD_NTT_ORDER = NTT::InputOutputOrder::NN;
static constexpr auto LDE_INVERSE_NTT_ORDER = NTT::InputOutputOrder::NN;
#else
static constexpr bool LDE_INPUT_BIT_REVERSED = true;
static constexpr auto LDE_FORWARD_NTT_ORDER = NTT::InputOutputOrder::RN;
static constexpr auto LDE_INVERSE_NTT_ORDER = NTT::InputOutputOrder::NR;
#endif

static cudaError_t run_ntt_batch(
    fr_t* data,
    uint32_t lg_domain_size,
    uint32_t poly_count,
    uint32_t stride,
    NTT::InputOutputOrder order,
    NTT::Direction direction,
    bool reverse_result,
    const cudaStream_t stream) {
    try {
#ifdef NVIDIA_NTT
        const bool reverse_input =
            order == NTT::InputOutputOrder::RN || order == NTT::InputOutputOrder::RR;
        const bool reverse_output =
            (order == NTT::InputOutputOrder::NN || order == NTT::InputOutputOrder::RN) !=
            reverse_result;
        if (reverse_input) {
            for (uint32_t polynomial = 0; polynomial < poly_count; ++polynomial) {
                NTT::bit_rev(
                    data + polynomial * stride,
                    data + polynomial * stride,
                    lg_domain_size,
                    stream);
            }
        }
        cudaError_t error = nvidia_ntt_batch(
            data,
            lg_domain_size,
            poly_count,
            stride,
            direction == NTT::Direction::inverse,
            stream);
        if (error != cudaSuccess) {
            return error;
        }
        if (reverse_output) {
            for (uint32_t polynomial = 0; polynomial < poly_count; ++polynomial) {
                NTT::bit_rev(
                    data + polynomial * stride,
                    data + polynomial * stride,
                    lg_domain_size,
                    stream);
            }
        }
#else
        for (uint32_t polynomial = 0; polynomial < poly_count; ++polynomial) {
            NTT::Base_dev_ptr(
                stream,
                data + polynomial * stride,
                lg_domain_size,
                order,
                direction,
                NTT::Type::standard);
        }
        if (reverse_result) {
            for (uint32_t polynomial = 0; polynomial < poly_count; ++polynomial) {
                NTT::bit_rev(
                    data + polynomial * stride,
                    data + polynomial * stride,
                    lg_domain_size,
                    stream);
            }
        }
#endif
    } catch (const cuda_error& error) {
        return static_cast<cudaError_t>(-error.code());
    }
    return cudaSuccess;
}

extern "C" rustCudaError_t sppark_init(const cudaStream_t stream) {
#ifdef NVIDIA_NTT
    return CUDA_SUCCESS_CSL;
#else
    uint32_t lg_domain_size = 1;
    uint32_t domain_size = 1U << lg_domain_size;

    std::vector<fr_t> inout(domain_size);
    inout[0] = fr_t(1);
    inout[1] = fr_t(1);
    try {
        NTT::Base(
            stream,
            &inout[0],
            lg_domain_size,
            NTT::InputOutputOrder::NR,
            NTT::Direction::forward,
            NTT::Type::standard);
    } catch (const cuda_error& error) {
        CUDA_OK(static_cast<cudaError_t>(-error.code()));
    }
    return CUDA_SUCCESS_CSL;
#endif
}

extern "C" rustCudaError_t dft_init_twiddles(
    uint32_t max_log_size,
    const cudaStream_t stream) {
#ifdef NVIDIA_NTT
    CUDA_OK(nvidia_ntt_init(max_log_size, stream));
#else
    (void)max_log_size;
    (void)stream;
#endif
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t batch_coset_dft(
    fr_t* d_out,
    fr_t* d_in,
    uint32_t lg_domain_size,
    uint32_t lg_blowup,
    fr_t shift,
    uint32_t poly_count,
    bool bit_rev_output,
    const cudaStream_t stream) {
    if (lg_domain_size == 0) {
        return CUDA_SUCCESS_CSL;
    }

    uint32_t domain_size = 1U << lg_domain_size;
    uint32_t ext_domain_size = domain_size << lg_blowup;

    try {
        const auto gen_powers = NTTParameters::all()[NTT::gpu_id()].partial_group_gen_powers;
        const bool perform_shift = shift != group_gen_inverse;
#ifdef NVIDIA_NTT
        const uint32_t lg_ext_domain_size = lg_domain_size + lg_blowup;
        if (lg_ext_domain_size >= 14) {
            CUDA_OK(nvidia_ntt_batch_coset(
                d_out,
                d_in,
                lg_ext_domain_size,
                lg_blowup,
                poly_count,
                &gen_powers[0][0],
                shift,
                perform_shift,
                stream));
            if (!bit_rev_output) {
                for (uint32_t polynomial = 0; polynomial < poly_count; ++polynomial) {
                    NTT::bit_rev(
                        d_out + polynomial * ext_domain_size,
                        d_out + polynomial * ext_domain_size,
                        lg_ext_domain_size,
                        stream);
                }
            }
            return CUDA_SUCCESS_CSL;
        }
#endif
        for (size_t c = 0; c < poly_count; c++) {
            fr_t* domain_data = &d_in[c * domain_size];
            if constexpr (LDE_INPUT_BIT_REVERSED) {
                domain_data = &d_out[(c + 1) * ext_domain_size - domain_size];
                NTT::bit_rev(
                    domain_data,
                    &d_in[c * domain_size],
                    lg_domain_size,
                    stream);
            }

            NTT::LDE_launch(
                stream,
                &d_out[c * ext_domain_size],
                domain_data,
                gen_powers,
                lg_domain_size,
                lg_blowup,
                LDE_INPUT_BIT_REVERSED,
                perform_shift,
                shift);

        }
        CUDA_OK(run_ntt_batch(
            d_out,
            lg_domain_size + lg_blowup,
            poly_count,
            ext_domain_size,
            LDE_FORWARD_NTT_ORDER,
            NTT::Direction::forward,
            bit_rev_output,
            stream));
    } catch (const cuda_error& error) {
        CUDA_OK(static_cast<cudaError_t>(-error.code()));
    }

    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t batch_coset_dft_in_place(
    fr_t* d_inout,
    uint32_t lg_domain_size,
    uint32_t lg_blowup,
    fr_t shift,
    uint32_t poly_count,
    bool bit_rev_output,
    const cudaStream_t stream) {
    if (lg_domain_size == 0) {
        return CUDA_SUCCESS_CSL;
    }

    uint32_t domain_size = 1U << lg_domain_size;
    uint32_t ext_domain_size = domain_size << lg_blowup;

    try {
        const auto gen_powers = NTTParameters::all()[NTT::gpu_id()].partial_group_gen_powers;
        const bool perform_shift = shift != group_gen_inverse;
        for (size_t c = 0; c < poly_count; c++) {
            fr_t* domain_data = &d_inout[(c + 1) * ext_domain_size - domain_size];
            if constexpr (LDE_INPUT_BIT_REVERSED) {
                NTT::bit_rev(domain_data, domain_data, lg_domain_size, stream);
            }

            NTT::LDE_launch(
                stream,
                &d_inout[c * ext_domain_size],
                domain_data,
                gen_powers,
                lg_domain_size,
                lg_blowup,
                LDE_INPUT_BIT_REVERSED,
                perform_shift,
                shift);

        }
        CUDA_OK(run_ntt_batch(
            d_inout,
            lg_domain_size + lg_blowup,
            poly_count,
            ext_domain_size,
            LDE_FORWARD_NTT_ORDER,
            NTT::Direction::forward,
            bit_rev_output,
            stream));
    } catch (const cuda_error& error) {
        CUDA_OK(static_cast<cudaError_t>(-error.code()));
    }

    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t batch_lde_shift_in_place(
    fr_t* d_inout,
    uint32_t lg_domain_size,
    uint32_t lg_blowup,
    fr_t shift,
    uint32_t poly_count,
    bool bit_rev_output,
    const cudaStream_t stream) {
    if (lg_domain_size == 0) {
        return CUDA_SUCCESS_CSL;
    }

    uint32_t domain_size = 1U << lg_domain_size;
    uint32_t ext_domain_size = domain_size << lg_blowup;

    try {
        const auto gen_powers = NTTParameters::all()[NTT::gpu_id()].partial_group_gen_powers;
        const bool perform_shift = shift != group_gen_inverse;
        CUDA_OK(run_ntt_batch(
            &d_inout[ext_domain_size - domain_size],
            lg_domain_size,
            poly_count,
            ext_domain_size,
            LDE_INVERSE_NTT_ORDER,
            NTT::Direction::inverse,
            false,
            stream));
        for (size_t c = 0; c < poly_count; c++) {
            NTT::LDE_launch(
                stream,
                &d_inout[c * ext_domain_size],
                &d_inout[(c + 1) * ext_domain_size - domain_size],
                gen_powers,
                lg_domain_size,
                lg_blowup,
                LDE_INPUT_BIT_REVERSED,
                perform_shift,
                shift);

        }
        CUDA_OK(run_ntt_batch(
            d_inout,
            lg_domain_size + lg_blowup,
            poly_count,
            ext_domain_size,
            LDE_FORWARD_NTT_ORDER,
            NTT::Direction::forward,
            bit_rev_output,
            stream));
    } catch (const cuda_error& error) {
        CUDA_OK(static_cast<cudaError_t>(-error.code()));
    }

    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
batch_NTT(fr_t* d_inout, uint32_t lg_domain_size, uint32_t poly_count, const cudaStream_t stream) {
    if (lg_domain_size == 0)
        return CUDA_SUCCESS_CSL;

    uint32_t domain_size = 1U << lg_domain_size;

    CUDA_OK(run_ntt_batch(
        d_inout,
        lg_domain_size,
        poly_count,
        domain_size,
        NTT::InputOutputOrder::NN,
        NTT::Direction::forward,
        false,
        stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t reverse_bits_batch(
    fr_t* d_out,
    fr_t* d_in,
    uint32_t lg_domain_size,
    uint32_t poly_count,
    const cudaStream_t stream) {
    if (lg_domain_size == 0)
        return CUDA_SUCCESS_CSL;

    uint32_t domain_size = 1U << lg_domain_size;

    try {
        for (size_t c = 0; c < poly_count; c++) {
            NTT::bit_rev(&d_out[c * domain_size], &d_in[c * domain_size], lg_domain_size, stream);
        }
    } catch (const cuda_error& error) {
        CUDA_OK(static_cast<cudaError_t>(-error.code()));
    }
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
batch_iNTT(fr_t* d_inout, uint32_t lg_domain_size, uint32_t poly_count, const cudaStream_t stream) {
    if (lg_domain_size == 0)
        return CUDA_SUCCESS_CSL;

    uint32_t domain_size = 1U << lg_domain_size;

    CUDA_OK(run_ntt_batch(
        d_inout,
        lg_domain_size,
        poly_count,
        domain_size,
        NTT::InputOutputOrder::NN,
        NTT::Direction::inverse,
        false,
        stream));
    return CUDA_SUCCESS_CSL;
}

#endif
