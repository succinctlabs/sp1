// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef __SPPARK_NTT_PARAMETERS_CUH__
#define __SPPARK_NTT_PARAMETERS_CUH__

// Maximum domain size supported. Can be adjusted at will, but with the
// target field in mind. Most fields handle up to 2^32 elements, BLS12-377
// can handle up to 2^47, alt_bn128 - 2^28...
#ifndef MAX_LG_DOMAIN_SIZE
# if defined(FEATURE_BN254)
#  define MAX_LG_DOMAIN_SIZE 28
# elif defined(FEATURE_KOALA_BEAR)
#  define MAX_LG_DOMAIN_SIZE 24
# else
#  define MAX_LG_DOMAIN_SIZE 28 // tested only up to 2^31 for now
# endif
#endif

#if MAX_LG_DOMAIN_SIZE <= 32
typedef unsigned int index_t;
#else
typedef size_t index_t;
#endif

#if defined(FEATURE_KOALA_BEAR)
# define LG_WINDOW_SIZE ((MAX_LG_DOMAIN_SIZE + 4) / 5)
#elif defined(FEATURE_GOLDILOCKS)
# if MAX_LG_DOMAIN_SIZE <= 28
#  define LG_WINDOW_SIZE ((MAX_LG_DOMAIN_SIZE + 3) / 4)
# else
#  define LG_WINDOW_SIZE ((MAX_LG_DOMAIN_SIZE + 4) / 5)
# endif
#else // 256-bit fields
# if MAX_LG_DOMAIN_SIZE <= 28
#  define LG_WINDOW_SIZE ((MAX_LG_DOMAIN_SIZE + 1) / 2)
# else
#  define LG_WINDOW_SIZE ((MAX_LG_DOMAIN_SIZE + 2) / 3)
# endif
#endif

#define WINDOW_SIZE (1 << LG_WINDOW_SIZE)
#define WINDOW_NUM ((MAX_LG_DOMAIN_SIZE + LG_WINDOW_SIZE - 1) / LG_WINDOW_SIZE)

__device__ __constant__ fr_t forward_radix6_twiddles[32] = {};
__device__ __constant__ fr_t inverse_radix6_twiddles[32] = {};

#ifndef __CUDA_ARCH__
# if defined(FEATURE_BLS12_377)
#  include "parameters/bls12_377.h"
# elif defined(FEATURE_BLS12_381)
#  include "parameters/bls12_381.h"
# elif defined(FEATURE_PALLAS)
#  include "parameters/vesta.h"     // Fr for Pallas curve is Vesta
# elif defined(FEATURE_VESTA)
#  include "parameters/pallas.h"    // Fr for Vesta curve is Pallas
# elif defined(FEATURE_BN254)
#  include "parameters/alt_bn128.h"
# elif defined(FEATURE_KOALA_BEAR)
#  include "parameters/koala_bear.h"
# elif defined(FEATURE_GOLDILOCKS)
#  include "parameters/goldilocks.h"
# endif
#else
extern const fr_t group_gen, group_gen_inverse;
extern const fr_t forward_roots_of_unity[];
extern const fr_t inverse_roots_of_unity[];
extern const fr_t domain_size_inverse[];
#endif

template<class fr_t> __global__
void generate_partial_twiddles(fr_t (*roots)[WINDOW_SIZE],
                               const fr_t root_of_unity)
{
    const unsigned int tid = threadIdx.x + blockDim.x * blockIdx.x;
    assert(tid < WINDOW_SIZE);
    fr_t root;

    root = root_of_unity^tid;

    roots[0][tid] = root;

    for (int off = 1; off < WINDOW_NUM; off++) {
        for (int i = 0; i < LG_WINDOW_SIZE; i++)
            root.sqr();
        roots[off][tid] = root;
    }
}

template<class fr_t> __global__
void generate_all_twiddles(fr_t* d_radixX_twiddles, const fr_t root6,
                                                    const fr_t root7,
                                                    const fr_t root8,
                                                    const fr_t root9,
                                                    const fr_t root10)
{
    const unsigned int tid = threadIdx.x + blockDim.x * blockIdx.x;
    unsigned int pow = 0;
    fr_t root_of_unity;

    if (tid < 64) {
        pow = tid;
        root_of_unity = root7;
    } else if (tid < 64 + 128) {
        pow = tid - 64;
        root_of_unity = root8;
    } else if (tid < 64 + 128 + 256) {
        pow = tid - 64 - 128;
        root_of_unity = root9;
    } else if (tid < 64 + 128 + 256 + 512) {
        pow = tid - 64 - 128 - 256;
        root_of_unity = root10;
    } else if (tid < 64 + 128 + 256 + 512 + 32) {
        pow = tid - 64 - 128 - 256 - 512;
        root_of_unity = root6;
    } else {
        assert(false);
    }

    d_radixX_twiddles[tid] = root_of_unity^pow;
}

template<class fr_t> __launch_bounds__(512) __global__
void generate_radixX_twiddles_X(fr_t* d_radixX_twiddles_X, int n,
                                const fr_t root_of_unity)
{
    if (gridDim.x == 1) {
        d_radixX_twiddles_X[threadIdx.x] = fr_t::one();
        d_radixX_twiddles_X += blockDim.x;

        fr_t root0 = root_of_unity^threadIdx.x;

        d_radixX_twiddles_X[threadIdx.x] = root0;
        d_radixX_twiddles_X += blockDim.x;

        fr_t root1 = root0;

        for (int i = 2; i < n; i++) {
            root1 *= root0;
            d_radixX_twiddles_X[threadIdx.x] = root1;
            d_radixX_twiddles_X += blockDim.x;
        }
    } else {
        fr_t root0 = root_of_unity^(threadIdx.x * gridDim.x);

        unsigned int pow = blockIdx.x * threadIdx.x;
        unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;

        fr_t root1 = root_of_unity^pow;

        d_radixX_twiddles_X[tid] = root1;
        d_radixX_twiddles_X += gridDim.x * blockDim.x;

        for (int i = gridDim.x; i < n; i += gridDim.x) {
            root1 *= root0;
            d_radixX_twiddles_X[tid] = root1;
            d_radixX_twiddles_X += gridDim.x * blockDim.x;
        }
    }
}

class NTTParameters {
private:
    bool inverse;

public:
    fr_t (*partial_twiddles)[WINDOW_SIZE];

    fr_t* twiddles[5];

    fr_t (*partial_group_gen_powers)[WINDOW_SIZE]; // for LDE

#if !defined(FEATURE_KOALA_BEAR) && !defined(FEATURE_GOLDILOCKS)
    fr_t* radix6_twiddles_6, * radix6_twiddles_12, * radix7_twiddles_7,
        * radix8_twiddles_8, * radix9_twiddles_9;

private:
    fr_t* twiddles_X(int num_blocks, int block_size, const fr_t& root)
    {
        fr_t* ret;
        CUDA_UNWRAP_SPPARK(cudaMalloc(&ret, num_blocks * block_size * sizeof(fr_t)));
        
        generate_radixX_twiddles_X<<<16, block_size, 0, stream>>>(ret, num_blocks, root);
        CUDA_UNWRAP_SPPARK(cudaGetLastError());
        return ret;
    }
#endif

public:
    NTTParameters(const bool _inverse)
        : inverse(_inverse)
    {
        const fr_t* roots = inverse ? inverse_roots_of_unity
                                    : forward_roots_of_unity;

        const size_t blob_sz = 64 + 128 + 256 + 512 + 32;

        fr_t* radix6_twiddles;
        CUDA_UNWRAP_SPPARK(cudaGetSymbolAddress((void**)&radix6_twiddles,
                                     inverse ? inverse_radix6_twiddles
                                             : forward_radix6_twiddles));

        fr_t* blob;
        CUDA_UNWRAP_SPPARK(cudaMalloc(&blob, blob_sz * sizeof(fr_t)));
        
        twiddles[0] = radix6_twiddles;
        twiddles[1] = blob;                 /* radix7_twiddles */
        twiddles[2] = twiddles[1] + 64;     /* radix8_twiddles */
        twiddles[3] = twiddles[2] + 128;    /* radix9_twiddles */
        twiddles[4] = twiddles[3] + 256;    /* radix10_twiddles */


        generate_all_twiddles<<<blob_sz/32, 32>>>(blob,
                                                          roots[6],
                                                          roots[7],
                                                          roots[8],
                                                          roots[9],
                                                          roots[10]);

        /* copy to the constant segment */
        CUDA_UNWRAP_SPPARK(cudaMemcpy(radix6_twiddles, twiddles[4] + 512,
                                32 * sizeof(fr_t), cudaMemcpyDeviceToDevice
                                ));

#if !defined(FEATURE_KOALA_BEAR) && !defined(FEATURE_GOLDILOCKS)
        radix6_twiddles_6 = twiddles_X(64, 64, roots[12]);
        radix6_twiddles_12 = twiddles_X(4096, 64, roots[18]);
        radix7_twiddles_7 = twiddles_X(128, 128, roots[14]);
        radix8_twiddles_8 = twiddles_X(256, 256, roots[16]);
        radix9_twiddles_9 = twiddles_X(512, 512, roots[18]);
#endif

        const size_t partial_sz = WINDOW_NUM * WINDOW_SIZE;

        CUDA_UNWRAP_SPPARK(cudaMalloc(&partial_twiddles, 2 * partial_sz * sizeof(fr_t)));

        partial_group_gen_powers = &partial_twiddles[WINDOW_NUM];

        generate_partial_twiddles<<<WINDOW_SIZE/32, 32>>>
            (partial_twiddles, roots[MAX_LG_DOMAIN_SIZE]);
        CUDA_UNWRAP_SPPARK(cudaGetLastError());

        generate_partial_twiddles<<<WINDOW_SIZE/32, 32>>>
            (partial_group_gen_powers, inverse ? group_gen_inverse 
                                               : group_gen);
        CUDA_UNWRAP_SPPARK(cudaGetLastError());
    }
    NTTParameters(const NTTParameters&) = delete;
    NTTParameters(NTTParameters&&) = default;

    ~NTTParameters()
    {
        cudaFree(partial_twiddles);

#if !defined(FEATURE_KOALA_BEAR) && !defined(FEATURE_GOLDILOCKS)
        cudaFree(radix9_twiddles_9);
        cudaFree(radix8_twiddles_8);
        cudaFree(radix7_twiddles_7);
        cudaFree(radix6_twiddles_12);
        cudaFree(radix6_twiddles_6);

#endif

        cudaFree(twiddles[1]);
    }


private:
    class all_params { friend class NTTParameters;
        std::vector<NTTParameters> forward;
        std::vector<NTTParameters> inverse;

        all_params()
        {
            int current_id;
            CUDA_UNWRAP_SPPARK(cudaGetDevice(&current_id));

            int nids = 0;
            CUDA_UNWRAP_SPPARK(cudaGetDeviceCount(&nids));

            forward.reserve(nids);
            inverse.reserve(nids);

            for (int id = 0; id < nids; id++) {
                CUDA_UNWRAP_SPPARK(cudaSetDevice(id));
                forward.emplace_back(false);
                inverse.emplace_back(true);
            }

            CUDA_UNWRAP_SPPARK(cudaSetDevice(current_id));
        }
    };

public:
    static const auto& all(bool inverse = false)
    {
        static all_params params;
        return inverse ? params.inverse : params.forward;
    }
};
#endif /* __SPPARK_NTT_PARAMETERS_CUH__ */
