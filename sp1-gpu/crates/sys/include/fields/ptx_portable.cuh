// Portable C++ replacements for NVIDIA PTX intrinsics.
// Used when compiling with HIP/ROCm for AMD GPUs.
// These functions produce identical results to the PTX versions
// and modern compilers generate optimal code for both architectures.

#pragma once

#include <cstdint>

// Ensure __device__ and __forceinline__ are defined
#ifdef __HIPCC__
#include <hip/hip_runtime.h>
#endif

// Pack two uint32_t into a uint64_t (low, high)
__device__ __forceinline__ void pack(uint64_t& d, uint32_t a0, uint32_t a1) {
    d = (uint64_t)a0 | ((uint64_t)a1 << 32);
}

// Unpack a uint64_t into two uint32_t (low, high)
__device__ __forceinline__ void unpack(uint32_t& d0, uint32_t& d1, uint64_t a) {
    d0 = (uint32_t)a;
    d1 = (uint32_t)(a >> 32);
}

// Add
__device__ __forceinline__ void add(uint32_t& d, uint32_t a, uint32_t b) {
    d = a + b;
}
__device__ __forceinline__ void add(uint64_t& d, uint64_t a, uint64_t b) {
    d = a + b;
}

// Sub
__device__ __forceinline__ void sub(uint32_t& d, uint32_t a, uint32_t b) {
    d = a - b;
}
__device__ __forceinline__ void sub(uint64_t& d, uint64_t a, uint64_t b) {
    d = a - b;
}

// Mul low word
__device__ __forceinline__ void mul_lo(uint32_t& d, uint32_t a, uint32_t b) {
    d = a * b;
}
__device__ __forceinline__ void mul_lo(uint64_t& d, uint64_t a, uint64_t b) {
    d = a * b;
}

// Mul high word
__device__ __forceinline__ void mul_hi(uint32_t& d, uint32_t a, uint32_t b) {
    d = (uint32_t)(((uint64_t)a * b) >> 32);
}
__device__ __forceinline__ void mul_hi(uint64_t& d, uint64_t a, uint64_t b) {
    d = (uint64_t)(__uint128_t(a) * b >> 64);
}

// Mul wide: uint32 x uint32 -> uint64
__device__ __forceinline__ void mul_wide(uint64_t& d, uint32_t a, uint32_t b) {
    d = (uint64_t)a * b;
}

// Mad (multiply-add) low word
__device__ __forceinline__ void mad_lo(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void mad_lo(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = a * b + c;
}

// Mad high word
__device__ __forceinline__ void mad_hi(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = (uint32_t)(((uint64_t)a * b) >> 32) + c;
}
__device__ __forceinline__ void mad_hi(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = (uint64_t)(__uint128_t(a) * b >> 64) + c;
}

// Mad wide: uint32 x uint32 + uint64 -> uint64
__device__ __forceinline__ void mad_wide(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    d = (uint64_t)a * b + c;
}

// Carry-chain operations: On AMD, we use regular operations.
// The carry flag is not exposed in C++, but for KoalaBear field arithmetic
// (31-bit field, single uint32_t values), carry chains are only used
// in the Montgomery reduction where we can use 64-bit arithmetic instead.

// add.cc / addc.cc / addc — carry chain add
// For SP1's KoalaBear field, these are only used in mont_t.cuh (multi-limb),
// not in kb31_t. We provide simple implementations.
__device__ __forceinline__ void add_cc(uint32_t& d, uint32_t a, uint32_t b) { d = a + b; }
__device__ __forceinline__ void add_cc(uint64_t& d, uint64_t a, uint64_t b) { d = a + b; }
__device__ __forceinline__ void addc_cc(uint32_t& d, uint32_t a, uint32_t b) { d = a + b; }
__device__ __forceinline__ void addc_cc(uint64_t& d, uint64_t a, uint64_t b) { d = a + b; }
__device__ __forceinline__ void addc(uint32_t& d, uint32_t a, uint32_t b) { d = a + b; }
__device__ __forceinline__ void addc(uint64_t& d, uint64_t a, uint64_t b) { d = a + b; }

// sub.cc / subc.cc / subc — carry chain subtract
__device__ __forceinline__ void sub_cc(uint32_t& d, uint32_t a, uint32_t b) { d = a - b; }
__device__ __forceinline__ void sub_cc(uint64_t& d, uint64_t a, uint64_t b) { d = a - b; }
__device__ __forceinline__ void subc_cc(uint32_t& d, uint32_t a, uint32_t b) { d = a - b; }
__device__ __forceinline__ void subc_cc(uint64_t& d, uint64_t a, uint64_t b) { d = a - b; }
__device__ __forceinline__ void subc(uint32_t& d, uint32_t a, uint32_t b) { d = a - b; }
__device__ __forceinline__ void subc(uint64_t& d, uint64_t a, uint64_t b) { d = a - b; }

// mad.lo.cc / mad.hi.cc — carry chain multiply-add
__device__ __forceinline__ void mad_lo_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void mad_lo_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void mad_hi_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = (uint32_t)(((uint64_t)a * b) >> 32) + c;
}
__device__ __forceinline__ void mad_hi_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = (uint64_t)(__uint128_t(a) * b >> 64) + c;
}

// madc.lo / madc.hi — multiply-add with carry in
__device__ __forceinline__ void madc_lo(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void madc_lo(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void madc_hi(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = (uint32_t)(((uint64_t)a * b) >> 32) + c;
}
__device__ __forceinline__ void madc_hi(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = (uint64_t)(__uint128_t(a) * b >> 64) + c;
}

// madc.lo.cc / madc.hi.cc
__device__ __forceinline__ void madc_lo_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void madc_lo_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = a * b + c;
}
__device__ __forceinline__ void madc_hi_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    d = (uint32_t)(((uint64_t)a * b) >> 32) + c;
}
__device__ __forceinline__ void madc_hi_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    d = (uint64_t)(__uint128_t(a) * b >> 64) + c;
}

// Wide mad.cc / madc.cc / madc — these are 2-instruction sequences on NVIDIA
// but single operations in C++
__device__ __forceinline__ void mad_wide_cc(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    d = (uint64_t)a * b + c;
}
__device__ __forceinline__ void madc_wide_cc(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    d = (uint64_t)a * b + c;
}
__device__ __forceinline__ void madc_wide(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    d = (uint64_t)a * b + c;
}
