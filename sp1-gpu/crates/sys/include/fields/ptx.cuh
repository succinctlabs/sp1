// Copyright 2022-2025 Dag Arne Osvik
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

// Pack

__device__ __forceinline__ void pack(uint64_t& d, uint32_t a0, uint32_t a1) {
    asm("\n\tmov.b64 %0, {%1, %2};" : "=l"(d) : "r"(a0), "r"(a1));
}

// Unpack

__device__ __forceinline__ void unpack(uint32_t& d0, uint32_t& d1, uint64_t a) {
    asm("\n\tmov.b64 {%0, %1}, %2;" : "=r"(d0), "=r"(d1) : "l"(a));
}

// Add

__device__ __forceinline__ void add(uint32_t& d, uint32_t a, uint32_t b) {
    asm("\n\tadd.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void add(uint64_t& d, uint64_t a, uint64_t b) {
    asm("\n\tadd.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void add_cc(uint32_t& d, uint32_t a, uint32_t b) {
    asm volatile("\n\tadd.cc.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void add_cc(uint64_t& d, uint64_t a, uint64_t b) {
    asm volatile("\n\tadd.cc.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void addc_cc(uint32_t& d, uint32_t a, uint32_t b) {
    asm volatile("\n\taddc.cc.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void addc_cc(uint64_t& d, uint64_t a, uint64_t b) {
    asm volatile("\n\taddc.cc.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void addc(uint32_t& d, uint32_t a, uint32_t b) {
    asm volatile("\n\taddc.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void addc(uint64_t& d, uint64_t a, uint64_t b) {
    asm volatile("\n\taddc.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

// Sub

__device__ __forceinline__ void sub(uint32_t& d, uint32_t a, uint32_t b) {
    asm("\n\tsub.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void sub(uint64_t& d, uint64_t a, uint64_t b) {
    asm("\n\tsub.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void sub_cc(uint32_t& d, uint32_t a, uint32_t b) {
    asm volatile("\n\tsub.cc.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void sub_cc(uint64_t& d, uint64_t a, uint64_t b) {
    asm volatile("\n\tsub.cc.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void subc_cc(uint32_t& d, uint32_t a, uint32_t b) {
    asm volatile("\n\tsubc.cc.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void subc_cc(uint64_t& d, uint64_t a, uint64_t b) {
    asm volatile("\n\tsubc.cc.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void subc(uint32_t& d, uint32_t a, uint32_t b) {
    asm volatile("\n\tsubc.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void subc(uint64_t& d, uint64_t a, uint64_t b) {
    asm volatile("\n\tsubc.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

// Mul

__device__ __forceinline__ void mul_lo(uint32_t& d, uint32_t a, uint32_t b) {
    asm("\n\tmul.lo.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void mul_lo(uint64_t& d, uint64_t a, uint64_t b) {
    asm("\n\tmul.lo.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void mul_hi(uint32_t& d, uint32_t a, uint32_t b) {
    asm("\n\tmul.hi.u32 %0, %1, %2;" : "=r"(d) : "r"(a), "r"(b));
}
__device__ __forceinline__ void mul_hi(uint64_t& d, uint64_t a, uint64_t b) {
    asm("\n\tmul.hi.u64 %0, %1, %2;" : "=l"(d) : "l"(a), "l"(b));
}

__device__ __forceinline__ void mul_wide(uint64_t& d, uint32_t a, uint32_t b) {
    asm("\n\tmul.wide.u32 %0, %1, %2;" : "=l"(d) : "r"(a), "r"(b));
}

// Mad

__device__ __forceinline__ void mad_lo(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm("\n\tmad.lo.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void mad_lo(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm("\n\tmad.lo.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

__device__ __forceinline__ void mad_hi(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm("\n\tmad.hi.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void mad_hi(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm("\n\tmad.hi.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

__device__ __forceinline__ void mad_wide(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    asm("\n\tmad.wide.u32 %0, %1, %2, %3;" : "=l"(d) : "r"(a), "r"(b), "l"(c));
}

// Mad.cc

__device__ __forceinline__ void mad_lo_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm volatile("\n\tmad.lo.cc.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void mad_lo_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm volatile("\n\tmad.lo.cc.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

__device__ __forceinline__ void mad_hi_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm volatile("\n\tmad.hi.cc.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void mad_hi_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm volatile("\n\tmad.hi.cc.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

// Madc

__device__ __forceinline__ void madc_lo(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm volatile("\n\tmadc.lo.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void madc_lo(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm volatile("\n\tmadc.lo.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

__device__ __forceinline__ void madc_hi(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm volatile("\n\tmadc.hi.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void madc_hi(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm volatile("\n\tmadc.hi.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

// Madc.cc

__device__ __forceinline__ void madc_lo_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm volatile("\n\tmadc.lo.cc.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void madc_lo_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm volatile("\n\tmadc.lo.cc.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

__device__ __forceinline__ void madc_hi_cc(uint32_t& d, uint32_t a, uint32_t b, uint32_t c) {
    asm volatile("\n\tmadc.hi.cc.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
}
__device__ __forceinline__ void madc_hi_cc(uint64_t& d, uint64_t a, uint64_t b, uint64_t c) {
    asm volatile("\n\tmadc.hi.cc.u64 %0, %1, %2, %3;" : "=l"(d) : "l"(a), "l"(b), "l"(c));
}

// Wide mad.cc, madc.cc, madc
// Two PTX instructions each, assembled to one SASS instruction (tested on Ampere)

__device__ __forceinline__ void mad_wide_cc(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    asm volatile("\n\t{"
                 "\n\t.reg.u64 tmp;"
                 "\n\tmul.wide.u32 tmp, %1, %2;"
                 "\n\tadd.cc.u64   %0, tmp, %3;"
                 "\n\t}"
                 : "=l"(d)
                 : "r"(a), "r"(b), "l"(c));
}

__device__ __forceinline__ void madc_wide_cc(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    asm volatile("\n\t{"
                 "\n\t.reg.u64 tmp;"
                 "\n\tmul.wide.u32 tmp, %1, %2;"
                 "\n\taddc.cc.u64  %0, tmp, %3;"
                 "\n\t}"
                 : "=l"(d)
                 : "r"(a), "r"(b), "l"(c));
}

__device__ __forceinline__ void madc_wide(uint64_t& d, uint32_t a, uint32_t b, uint64_t c) {
    asm volatile("\n\t{"
                 "\n\t.reg.u64 tmp;"
                 "\n\tmul.wide.u32 tmp, %1, %2;"
                 "\n\taddc.u64     %0, tmp, %3;"
                 "\n\t}"
                 : "=l"(d)
                 : "r"(a), "r"(b), "l"(c));
}
