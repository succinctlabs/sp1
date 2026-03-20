// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifdef __HIPCC__

#pragma clang diagnostic ignored "-Wdeprecated-pragma"
#ifndef __AMDGCN_WAVEFRONT_SIZE
# ifdef __GFX9__
#  define __AMDGCN_WAVEFRONT_SIZE 64
# else
#  define __AMDGCN_WAVEFRONT_SIZE 32
# endif
#endif

/*
 * AMD GPU architecture classification macros.
 *
 * __SPPARK_AMD_CDNA__  - CDNA/GCN5 (gfx9xx: MI100/MI200/MI300)
 *                        Wave64, large L2/Infinity Cache, HBM.
 * __SPPARK_AMD_RDNA__  - RDNA (gfx10xx/11xx/12xx: RX 5000-9000 series)
 *                        Wave32, smaller L2, consumer GPUs.
 *
 * Derived from compiler-builtin __GFX*__ family macros (ROCm 5.x+).
 * Individual target macros (__gfx942__, __gfx1201__, etc.) remain
 * available for fine-grained tuning.
 */
#ifdef __GFX9__
# define __SPPARK_AMD_CDNA__
#elif defined(__GFX10__) || defined(__GFX11__) || defined(__GFX12__)
# define __SPPARK_AMD_RDNA__
#endif

/*
 * Disable native ROCm 7.2+ warp sync builtins (__ballot_sync, __shfl_sync,
 * __activemask, etc.) so that our own polyfills below — which correctly
 * partition 64-wide wavefronts into virtual 32-lane warps — are used instead.
 */
#define HIP_DISABLE_WARP_SYNC_BUILTINS

#include <hip/hip_runtime.h>
#ifdef NDEBUG
# define assert(e) (void)(e)
#else
# include <cassert>
#endif

static const auto cudaGetDeviceCount        = hipGetDeviceCount;
static const auto cudaGetDevice             = hipGetDevice;
static const auto cudaSetDevice             = hipSetDevice;
static const auto cudaDeviceSynchronize     = hipDeviceSynchronize;
static const auto cudaDeviceGetAttribute    = hipDeviceGetAttribute;
#define           cudaDevAttrMultiProcessorCount hipDeviceAttributeMultiprocessorCount
#define           cudaDevAttrMaxThreadsPerBlock  hipDeviceAttributeMaxThreadsPerBlock

static const auto cudaStreamCreate          = hipStreamCreate;

using cudaDeviceProp                        = hipDeviceProp_t;
static const auto cudaGetDeviceProperties   = hipGetDeviceProperties;
static const auto cudaMemGetInfo            = hipMemGetInfo;

using cudaMemcpyKind                        = hipMemcpyKind;
static const auto cudaMemcpy                = hipMemcpy;
static const auto cudaMemcpyAsync           = hipMemcpyAsync;
static const auto cudaMemcpy2D              = hipMemcpy2D;
static const auto cudaMemcpy2DAsync         = hipMemcpy2DAsync;
#define           cudaMemcpyHostToDevice      hipMemcpyHostToDevice
#define           cudaMemcpyDeviceToHost      hipMemcpyDeviceToHost
#define           cudaMemcpyDeviceToDevice    hipMemcpyDeviceToDevice
static const auto cudaMemset                = hipMemset;
static const auto cudaMemsetAsync           = hipMemsetAsync;

using cudaError_t                           = hipError_t;
static const auto cudaGetLastError          = hipGetLastError;
static const auto cudaGetErrorString        = hipGetErrorString;
#define           cudaSuccess                 hipSuccess
#define           cudaErrorNoDevice           hipErrorNoDevice
#define           cudaErrorUnknown            hipErrorUnknown

using cudaLimit                             = hipLimit_t;
#define           cudaLimitStackSize          hipLimitStackSize
static const auto cudaDeviceSetLimit        = hipDeviceSetLimit;

// hipMemcpyToSymbol requires the symbol to be resolved at the call site
// (HIP_SYMBOL(X) on AMD is just X). A template wrapper would break the
// symbol resolution, so we use macros.
#define cudaMemcpyToSymbol(symbol, src, count) \
    hipMemcpyToSymbol(HIP_SYMBOL(symbol), (src), (count), 0, hipMemcpyHostToDevice)
#define cudaMemcpyToSymbolAsync(symbol, src, count, offset, kind, stream) \
    hipMemcpyToSymbolAsync(HIP_SYMBOL(symbol), (src), (count), (offset), (kind), (stream))

using cudaFuncCache                         = hipFuncCache_t;
#define           cudaFuncCachePreferL1       hipFuncCachePreferL1

template<typename T>
static inline cudaError_t cudaFuncSetCacheConfig(T func, cudaFuncCache cacheConfig)
{   return hipFuncSetCacheConfig(reinterpret_cast<const void*>(func), cacheConfig);   }

using cudaEvent_t                           = hipEvent_t;
static const auto cudaEventCreate           = hipEventCreate;
static const auto cudaEventCreateWithFlags  = hipEventCreateWithFlags;
#define           cudaEventDisableTiming      hipEventDisableTiming
static const auto cudaEventRecord           = hipEventRecord;
static const auto cudaEventDestroy          = hipEventDestroy;
static const auto cudaEventSynchronize      = hipEventSynchronize;
static const auto cudaEventElapsedTime      = hipEventElapsedTime;

using cudaStream_t                          = hipStream_t;
static const auto cudaStreamCreateWithFlags = hipStreamCreateWithFlags;
#define           cudaStreamNonBlocking       hipStreamNonBlocking
static const auto cudaStreamDestroy         = hipStreamDestroy;
static const auto cudaStreamSynchronize     = hipStreamSynchronize;
static const auto cudaStreamWaitEvent       = hipStreamWaitEvent;

using cudaHostFn_t                          = hipHostFn_t;
static const auto cudaLaunchHostFunc        = hipLaunchHostFunc;

template<typename T>
static inline cudaError_t cudaMalloc(T** devPtr, size_t size)
{   return hipMalloc(devPtr, size);   }
static const auto cudaFree                  = hipFree;

template<typename T>
static inline cudaError_t cudaMallocAsync(T** devPtr, size_t size,
                                          cudaStream_t stream)
{   return hipMallocAsync(devPtr, size, stream);   }
static const auto cudaFreeAsync             = hipFreeAsync;

using cudaMemPool_t                        = hipMemPool_t;
static const auto cudaDeviceGetDefaultMemPool = hipDeviceGetDefaultMemPool;
static const auto cudaMemPoolTrimTo        = hipMemPoolTrimTo;

template<typename T>
static inline cudaError_t cudaMallocManaged(T** uniPtr, size_t size)
{   return hipMallocManaged(uniPtr, size);   }

#define cudaHostAllocDefault                  hipHostMallocDefault
#define cudaHostAllocPortable                 hipHostMallocPortable
#define cudaHostAllocaMapped                  hipHostMallocMapped
#define cudaHostAllocWriteCombined            hipHostMallocWriteCombined
template<typename T>
static inline cudaError_t cudaHostAlloc(T** pinnedPtr, size_t size,
                                        unsigned int flags = hipHostMallocDefault)
{   return hipHostMalloc(pinnedPtr, size, flags);   }
template<typename T>
static inline cudaError_t cudaMallocHost(T** pinnedPtr, size_t size)
{   return hipHostMalloc(pinnedPtr, size, hipHostMallocDefault);   }
static const auto cudaFreeHost              = hipHostFree;

static const auto cudaHostRegister          = hipHostRegister;
static const auto cudaHostUnregister        = hipHostUnregister;
#define           cudaHostRegisterDefault    hipHostRegisterDefault
#define           cudaHostRegisterReadOnly   hipHostRegisterReadOnly
static const auto cudaHostGetDevicePointer  = hipHostGetDevicePointer;
static const auto cudaHostGetFlags          = hipHostGetFlags;

template<typename T>
static inline cudaError_t cudaGetSymbolAddress(void** devPtr, const T& symbol)
{   return hipGetSymbolAddress(devPtr, symbol);   }

template<typename T>
static inline cudaError_t
cudaOccupancyMaxPotentialBlockSize(int* minGridSize, int* blockSize, T func,
                                   size_t dynamicSMemSize = 0,
                                   int blockSizeLimit = 0)
{   return hipOccupancyMaxPotentialBlockSize(minGridSize, blockSize, func,
                                             dynamicSMemSize, blockSizeLimit);
}

using cudaFuncAttributes                    = hipFuncAttributes;

template<typename T>
static inline cudaError_t
cudaFuncGetAttributes(cudaFuncAttributes* attr, T func)
{   return hipFuncGetAttributes(attr, reinterpret_cast<const void*>(func));   }

using cudaFuncAttribute                    = hipFuncAttribute;
#define cudaFuncAttributeMaxDynamicSharedMemorySize \
        hipFuncAttributeMaxDynamicSharedMemorySize

template<typename T>
static inline cudaError_t
cudaFuncSetAttribute(T func, cudaFuncAttribute attr, int value)
{   return hipFuncSetAttribute(reinterpret_cast<const void*>(func),
                                attr, value);
}

template<typename T>
static inline cudaError_t
cudaLaunchCooperativeKernel(const T* func, dim3 gridDim, dim3 blockDim,
                            void** args, size_t sharedMem = 0,
                            cudaStream_t stream = 0)
{   return hipLaunchCooperativeKernel(func, gridDim, blockDim, args, sharedMem,
                                      stream);
}

static inline __device__ void __syncwarp()
{   __builtin_amdgcn_wave_barrier();
}

/*
 * Provide __activemask() that returns a 32-bit virtual-warp mask,
 * since the native ROCm 7.2 version is disabled by
 * HIP_DISABLE_WARP_SYNC_BUILTINS above.
 */
__device__ __forceinline__
static unsigned long long __activemask() { return __ballot(true); }

/*
 * To match CUDA, the 3-argument polyfills below are designed to produce
 * a result as if the wavefront size is 32 irregardless of its actual size.
 * They don't follow the CUDA semantics exactly and rely on indices to be
 * properly vetted by the caller, all in the name of minimizing the amount
 * of instructions. If in doubt, add WARP_SZ as the fourth argument to opt
 * for the more expensive ROCm primitives.
 *
 * A note about 'assert(mask == 0xffffffff);'. The mask is customarily
 * passed as a literal, in which case the assertion is bound to be
 * optimized away.
 */

#define WARP_SZ 32

template<typename T> __device__ __forceinline__
static T __shfl_sync(uint32_t mask, const T& src, int idx)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    int bperm = (idx + (threadIdx.x & (0-WARP_SZ))) * (int)sizeof(uint32_t);
    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __builtin_amdgcn_ds_bpermute(bperm, ret.vec[i]);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_sync(uint32_t mask, const T& src, int idx, int warpsz)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __shfl(ret.vec[i], idx, warpsz);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_up_sync(uint32_t mask, const T& src, uint32_t off)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    uint32_t idx = threadIdx.x - off;
    idx *= sizeof(uint32_t);
    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __builtin_amdgcn_ds_bpermute(idx, ret.vec[i]);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_up_sync(uint32_t mask, const T& src, unsigned int off, int warpsz)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __shfl_up(ret.vec[i], off, warpsz);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_down_sync(uint32_t mask, const T& src, uint32_t off)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    uint32_t idx = threadIdx.x + off;
    idx *= sizeof(uint32_t);
    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __builtin_amdgcn_ds_bpermute(idx, ret.vec[i]);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_down_sync(uint32_t mask, const T& src, unsigned int off, int warpsz)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __shfl_down(ret.vec[i], off, warpsz);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_xor_sync(uint32_t mask, const T& src, int laneMask)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    int idx = (threadIdx.x ^ laneMask) * (int)sizeof(uint32_t);
    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __builtin_amdgcn_ds_bpermute(idx, ret.vec[i]);

    return ret.val;
}

template<typename T> __device__ __forceinline__
static T __shfl_xor_sync(uint32_t mask, const T& src, int laneMask, int warpsz)
{
    assert(mask == 0xffffffff);

    const size_t len = sizeof(T)/sizeof(uint32_t);
    union { T val; uint32_t vec[len]; } ret{src};

    for (size_t i = 0; i < len; i++)
        ret.vec[i] = __shfl_xor(ret.vec[i], laneMask, warpsz);

    return ret.val;
}

/*
 * Mimic CUDA __ballot_sync by "splitting" wider wavefronts to halves.
 * We always provide these non-template overloads so that code using
 * virtual WARP_SZ=32 gets the correct per-half ballot result, even on
 * ROCm 7.2+ where the native __ballot_sync template returns a full
 * 64-bit mask.  Non-template overloads are preferred over the native
 * template during overload resolution, so there is no ambiguity.
 */
__device__ __forceinline__
static uint32_t __ballot_sync(uint32_t mask, bool predicate)
{
    assert(mask == 0xffffffff);

    uint64_t ret = __ballot(predicate);

    if (__AMDGCN_WAVEFRONT_SIZE == 64) {
        return (uint32_t)((threadIdx.x & WARP_SZ) ? ret>>32 : ret);
    } else {
        asm("" : "+v"(ret)); /* work around[?] a compiler bug */
        return (uint32_t)ret;
    }
}

/* Overload for ROCm 7.2+ where __activemask() returns unsigned long long. */
__device__ __forceinline__
static uint32_t __ballot_sync(unsigned long long mask, bool predicate)
{
    (void)mask;

    uint64_t ret = __ballot(predicate);

    if (__AMDGCN_WAVEFRONT_SIZE == 64) {
        return (uint32_t)((threadIdx.x & WARP_SZ) ? ret>>32 : ret);
    } else {
        asm("" : "+v"(ret)); /* work around[?] a compiler bug */
        return (uint32_t)ret;
    }
}

#ifdef NDEBUG
# undef assert
#endif
#endif
