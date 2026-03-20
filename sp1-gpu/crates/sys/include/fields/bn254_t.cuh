#pragma once

#ifdef __HIPCC__
// HIP stub: bn254_t uses mont_t which has PTX asm.
// The MultiField32Challenger path using BN254 is not used on AMD.
// Provide a minimal struct so challenger.cuh and poseidon2.cuh compile.
#include <cstdint>
struct bn254_t {
    uint32_t data[8]; // 256-bit BN254 field element
    __device__ bn254_t() {}
    __device__ void set_to_zero() { for (int i = 0; i < 8; i++) data[i] = 0; }
    __device__ uint32_t& operator[](size_t i) { return data[i]; }
    __device__ const uint32_t& operator[](size_t i) const { return data[i]; }
    __device__ bn254_t& operator+=(const bn254_t&) { return *this; }
    __device__ bn254_t& operator^=(int) { return *this; }
    __device__ void from() {} // no-op stub
    static __device__ bn254_t zero() { bn254_t r; r.set_to_zero(); return r; }
};
#else
#include "fields/alt_bn128.hpp"
using bn254_t = fr_mont;
#endif