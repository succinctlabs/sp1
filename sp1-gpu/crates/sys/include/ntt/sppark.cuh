
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

#include "runtime/exception.cuh"

#ifndef __CUDA_ARCH__

extern "C" rustCudaError_t sppark_init(const cudaStream_t stream) {
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
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
    }
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

    const auto gen_powers = NTTParameters::all()[NTT::gpu_id()].partial_group_gen_powers;

    try {
        for (size_t c = 0; c < poly_count; c++) {

            NTT::bit_rev(
                &d_out[(c + 1) * ext_domain_size - domain_size],
                &d_in[c * domain_size],
                lg_domain_size,
                stream);

            NTT::LDE_launch(
                stream,
                &d_out[c * ext_domain_size],
                &d_out[(c + 1) * ext_domain_size - domain_size],
                gen_powers,
                lg_domain_size,
                lg_blowup,
                true,
                shift);

            NTT::Base_dev_ptr(
                stream,
                &d_out[c * ext_domain_size],
                lg_domain_size + lg_blowup,
                NTT::InputOutputOrder::RN,
                NTT::Direction::forward,
                NTT::Type::standard);

            if (bit_rev_output) {
                NTT::bit_rev(
                    &d_out[c * ext_domain_size],
                    &d_out[c * ext_domain_size],
                    lg_domain_size + lg_blowup,
                    stream);
            }
        }
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
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

    const auto gen_powers = NTTParameters::all()[NTT::gpu_id()].partial_group_gen_powers;

    try {
        for (size_t c = 0; c < poly_count; c++) {

            NTT::bit_rev(
                &d_inout[(c + 1) * ext_domain_size - domain_size],
                &d_inout[(c + 1) * ext_domain_size - domain_size],
                lg_domain_size,
                stream);

            NTT::LDE_launch(
                stream,
                &d_inout[c * ext_domain_size],
                &d_inout[(c + 1) * ext_domain_size - domain_size],
                gen_powers,
                lg_domain_size,
                lg_blowup,
                true,
                shift);

            NTT::Base_dev_ptr(
                stream,
                &d_inout[c * ext_domain_size],
                lg_domain_size + lg_blowup,
                NTT::InputOutputOrder::RN,
                NTT::Direction::forward,
                NTT::Type::standard);

            if (bit_rev_output) {
                NTT::bit_rev(
                    &d_inout[c * ext_domain_size],
                    &d_inout[c * ext_domain_size],
                    lg_domain_size + lg_blowup,
                    stream);
            }
        }
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
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

    const auto gen_powers = NTTParameters::all()[NTT::gpu_id()].partial_group_gen_powers;

    try {
        for (size_t c = 0; c < poly_count; c++) {
            NTT::Base_dev_ptr(
                stream,
                &d_inout[(c + 1) * ext_domain_size - domain_size],
                lg_domain_size,
                NTT::InputOutputOrder::NR,
                NTT::Direction::inverse,
                NTT::Type::standard);

            NTT::LDE_launch(
                stream,
                &d_inout[c * ext_domain_size],
                &d_inout[(c + 1) * ext_domain_size - domain_size],
                gen_powers,
                lg_domain_size,
                lg_blowup,
                true,
                shift);

            NTT::Base_dev_ptr(
                stream,
                &d_inout[c * ext_domain_size],
                lg_domain_size + lg_blowup,
                NTT::InputOutputOrder::RN,
                NTT::Direction::forward,
                NTT::Type::standard);

            if (bit_rev_output) {
                NTT::bit_rev(
                    &d_inout[c * ext_domain_size],
                    &d_inout[c * ext_domain_size],
                    lg_domain_size + lg_blowup,
                    stream);
            }
        }
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
    }

    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
batch_NTT(fr_t* d_inout, uint32_t lg_domain_size, uint32_t poly_count, const cudaStream_t stream) {
    if (lg_domain_size == 0)
        return CUDA_SUCCESS_CSL;

    uint32_t domain_size = 1U << lg_domain_size;

    try {
        for (size_t c = 0; c < poly_count; c++) {
            NTT::Base_dev_ptr(
                stream,
                &d_inout[c * domain_size],
                lg_domain_size,
                NTT::InputOutputOrder::NN,
                NTT::Direction::forward,
                NTT::Type::standard);
        }
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
    }
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
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
    }
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
batch_iNTT(fr_t* d_inout, uint32_t lg_domain_size, uint32_t poly_count, const cudaStream_t stream) {
    if (lg_domain_size == 0)
        return CUDA_SUCCESS_CSL;

    uint32_t domain_size = 1U << lg_domain_size;

    try {
        for (size_t c = 0; c < poly_count; c++) {
            NTT::Base_dev_ptr(
                stream,
                &d_inout[c * domain_size],
                lg_domain_size,
                NTT::InputOutputOrder::NN,
                NTT::Direction::inverse,
                NTT::Type::standard);
        }
    } catch (const cudaError_t& e) {
        CUDA_OK(e);
    }
    return CUDA_SUCCESS_CSL;
}

#endif