// Modified by Succinct Labs
// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cassert>
#include <cstdint>

#include "fields/ptx.cuh"

#ifdef __CUDA_ARCH__

#define inline __device__ __forceinline__
#ifdef __GNUC__
#define asm __asm__ __volatile__
#else
#define asm asm volatile
#endif

class kb31_t {
  public:
    // Nested helper class for avoiding unnecessary modular reductions

    class accel_t {
      public:
        accel_t() = default;
        accel_t(const accel_t&) = default;
        __host__ __device__ accel_t(const uint64_t& x) : val(x) {}

        __device__ accel_t& operator+=(const kb31_t&);
        __device__ accel_t& operator-=(const kb31_t&);
        __device__ accel_t& operator*=(const kb31_t&);

        __device__ accel_t operator+(const kb31_t&) const;
        __device__ accel_t operator-(const kb31_t&) const;
        __device__ accel_t operator*(const kb31_t&) const;

        __device__ accel_t& operator+=(const accel_t&);
        __device__ accel_t& operator-=(const accel_t&);

        __device__ accel_t operator+(const accel_t&) const;
        __device__ accel_t operator-(const accel_t&) const;

        __device__ accel_t& add(const kb31_t*, uint32_t count, uint32_t stride);

        __device__ operator kb31_t() const {
            uint32_t tl, th, red;

            unpack(tl, th, val);

            mul_lo(red, tl, M);
            mad_lo_cc(tl, red, MOD, tl);
            madc_hi(th, red, MOD, th);

            final_sub(th);

            return kb31_t(th);
        }

      private:
        uint64_t val;
    };

    __device__ kb31_t& operator=(const accel_t& x) { // Reduce and assign
        kb31_t t(x);
        *this = t;
    }

    using mem_t = kb31_t;
    uint32_t val;
    static const uint32_t DEGREE = 1;
    static const uint32_t NBITS = 31;
    // The prime modulus of the KoalaBear field.
    static const uint32_t MOD = 0x7f000001u;
    // MOD - 2
    static const uint32_t M = 0x7effffff;
    // (1<<MONTY_BITS)^2 mod MOD
    static const uint32_t RR = 0x17f7efe4u;
    // (1<<MONTY_BITS) mod MOD
    static const uint32_t ONE = 0x01fffffeu;
    static const uint32_t MONTY_BITS = 32;
    // MOD^{-1} mod (1<<MONTY_BITS)
    static const uint32_t MONTY_MU = 0x81000001;
    static const uint32_t MONTY_MASK = ((1ULL << MONTY_BITS) - 1);

    static constexpr size_t __device__ bit_length() { return 31; }

    inline uint32_t& operator[](size_t i) { return val; }

    inline uint32_t& operator*() { return val; }

    inline const uint32_t& operator[](size_t i) const { return val; }

    inline uint32_t operator*() const { return val; }

    __host__ __device__ bool operator!=(const kb31_t& x) const { return val != x.val; }

    inline size_t len() const { return 1; }

    __host__ __device__ constexpr kb31_t() = default;

    inline constexpr kb31_t(const uint32_t a) : val(a) {}

    inline kb31_t(const uint32_t* p) { val = *p; }

    inline constexpr kb31_t(int a) : val(((uint64_t)a << 32) % MOD) {}

    static inline const kb31_t zero() { return kb31_t(0); }

    static inline const kb31_t one() { return kb31_t(ONE); }

    static inline const kb31_t two() { return from_canonical_u32(2); }

    static inline constexpr uint32_t to_monty(uint32_t x) {
        return (((uint64_t)x << MONTY_BITS) % MOD);
    }

    static inline uint32_t monty_reduce(uint64_t x) {
        uint64_t t = (x * (uint64_t)MONTY_MU) & (uint64_t)MONTY_MASK;
        uint64_t u = t * (uint64_t)MOD;
        uint64_t x_sub_u = x - u;
        bool over = x < u;
        uint32_t x_sub_u_hi = (uint32_t)(x_sub_u >> MONTY_BITS);
        uint32_t corr = over ? MOD : 0;
        return x_sub_u_hi + corr;
    }

    static inline uint32_t from_monty(uint32_t x) { return monty_reduce((uint64_t)x); }

    static inline kb31_t from_canonical_u32(uint32_t x) { return kb31_t(to_monty(x)); }

    static inline kb31_t from_canonical_u16(uint16_t x) { return from_canonical_u32((uint32_t)x); }

    static inline kb31_t from_canonical_u8(uint8_t x) { return from_canonical_u32((uint32_t)x); }

    static inline kb31_t load(kb31_t* ptr, int i) { return ptr[i]; }

    static inline const kb31_t load(const kb31_t* ptr, int i) { return ptr[i]; }

    static inline void store(kb31_t* ptr, int i, kb31_t value) { ptr[i] = value; }

    static inline kb31_t from_bool(bool x) { return kb31_t(x * one().val); }

    inline uint32_t as_canonical_u32() const { return monty_reduce((uint64_t)val); }

    inline kb31_t exp_power_of_two(size_t log_power) {
        kb31_t ret = *this;
        for (size_t i = 0; i < log_power; i++) {
            ret *= ret;
        }
        return ret;
    }

    inline kb31_t& operator+=(const kb31_t b) {
        val += b.val;
        final_sub(val);

        return *this;
    }

    friend inline kb31_t operator+(kb31_t a, const kb31_t b) { return a += b; }

    inline kb31_t& operator<<=(uint32_t l) {
        while (l--) {
            val <<= 1;
            final_sub(val);
        }

        return *this;
    }

    friend inline kb31_t operator<<(kb31_t a, uint32_t l) { return a <<= l; }

    inline kb31_t& operator>>=(uint32_t r) {
        while (r--) {
            val += val & 1 ? MOD : 0;
            val >>= 1;
        }

        return *this;
    }

    friend inline kb31_t operator>>(kb31_t a, uint32_t r) { return a >>= r; }

    inline kb31_t& operator-=(const kb31_t b) {
        asm("{");
        asm(".reg.pred %brw;");
        asm("setp.lt.u32 %brw, %0, %1;" ::"r"(val), "r"(b.val));
        asm("sub.u32 %0, %0, %1;" : "+r"(val) : "r"(b.val));
        asm("@%brw add.u32 %0, %0, %1;" : "+r"(val) : "r"(MOD));
        asm("}");

        return *this;
    }

    friend inline kb31_t operator-(kb31_t a, const kb31_t b) { return a -= b; }

    inline kb31_t cneg(bool flag) {
        asm("{");
        asm(".reg.pred %flag;");
        asm("setp.ne.u32 %flag, %0, 0;" ::"r"(val));
        asm("@%flag setp.ne.u32 %flag, %0, 0;" ::"r"((int)flag));
        asm("@%flag sub.u32 %0, %1, %0;" : "+r"(val) : "r"(MOD));
        asm("}");

        return *this;
    }

    static inline kb31_t cneg(kb31_t a, bool flag) { return a.cneg(flag); }

    inline kb31_t operator-() const { return cneg(*this, true); }

    inline bool operator==(const kb31_t rhs) const { return val == rhs.val; }

    inline bool is_one() const { return val == ONE; }

    inline bool is_zero() const { return val == 0; }

    inline void set_to_zero() { val = 0; }

    friend inline kb31_t czero(const kb31_t a, int set_z) {
        kb31_t ret;

        asm("{");
        asm(".reg.pred %set_z;");
        asm("setp.ne.s32 %set_z, %0, 0;" : : "r"(set_z));
        asm("selp.u32 %0, 0, %1, %set_z;" : "=r"(ret.val) : "r"(a.val));
        asm("}");

        return ret;
    }

    static inline kb31_t csel(const kb31_t a, const kb31_t b, int sel_a) {
        kb31_t ret;

        asm("{");
        asm(".reg.pred %sel_a;");
        asm("setp.ne.s32 %sel_a, %0, 0;" ::"r"(sel_a));
        asm("selp.u32 %0, %1, %2, %sel_a;" : "=r"(ret.val) : "r"(a.val), "r"(b.val));
        asm("}");

        return ret;
    }

  private:
    static inline void final_sub(uint32_t& val) { val = val >= MOD ? val - MOD : val; }

    // Montgomery multiplication

    inline kb31_t& mul(const kb31_t b) {
        uint64_t t;
        uint32_t tl, th, red;

        mul_wide(t, val, b.val);
        unpack(tl, th, t);
        mul_lo(red, tl, M);
        mad_lo_cc(tl, red, MOD, tl);
        madc_hi(val, red, MOD, th);

        final_sub(val);

        return *this;
    }

    inline uint32_t mul_by_1() const {
        uint32_t tmp[2], red;

        asm("mul.lo.u32 %0, %1, %2;" : "=r"(red) : "r"(val), "r"(M));
        asm("mad.lo.cc.u32 %0, %2, %3, %4; madc.hi.u32 %1, %2, %3, 0;"
            : "=r"(tmp[0]), "=r"(tmp[1])
            : "r"(red), "r"(MOD), "r"(val));
        return tmp[1];
    }

  public:
    inline accel_t operator*(const kb31_t b) const {
        uint64_t t;
        mul_wide(t, val, b.val);
        return accel_t(t);
    }

    inline kb31_t& operator*=(const kb31_t a) { return mul(a); }

    // raise to a variable power, variable in respect to threadIdx,
    // but mind the ^ operator's precedence!
    inline kb31_t& operator^=(uint32_t p) {
        kb31_t sqr = *this;
        *this = csel(val, ONE, p & 1);

#pragma unroll 1
        while (p >>= 1) {
            sqr.mul(sqr);
            if (p & 1)
                mul(sqr);
        }

        return *this;
    }

    friend inline kb31_t operator^(kb31_t a, uint32_t p) { return a ^= p; }

    inline kb31_t operator()(uint32_t p) { return *this ^ p; }

    // raise to a constant power, e.g. x^7, to be unrolled at compile time
    inline kb31_t& operator^=(int p) {
        if (p < 2)
            asm("trap;");

        kb31_t sqr = *this;
        if ((p & 1) == 0) {
            do {
                sqr.mul(sqr);
                p >>= 1;
            } while ((p & 1) == 0);
            *this = sqr;
        }
        for (p >>= 1; p; p >>= 1) {
            sqr.mul(sqr);
            if (p & 1)
                mul(sqr);
        }

        return *this;
    }

    friend inline kb31_t operator^(kb31_t a, int p) { return a ^= p; }

    inline kb31_t operator()(int p) { return *this ^ p; }

    inline kb31_t square() { return *this * *this; }

    friend inline kb31_t sqr(kb31_t a) { return a.sqr(); }

    inline kb31_t& sqr() { return mul(*this); }

    inline void to() { mul(RR); }

    inline void from() { val = mul_by_1(); }

    template <size_t T>
    static inline kb31_t dot_product(const kb31_t a[T], const kb31_t b[T]) {
        uint32_t acc[2];
        size_t i = 1;

        asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"
            : "=r"(acc[0]), "=r"(acc[1])
            : "r"(*a[0]), "r"(*b[0]));
        if ((T & 1) == 0) {
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
                : "+r"(acc[0]), "+r"(acc[1])
                : "r"(*a[i]), "r"(*b[i]));
            i++;
        }
        for (; i < T; i += 2) {
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
                : "+r"(acc[0]), "+r"(acc[1])
                : "r"(*a[i]), "r"(*b[i]));
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
                : "+r"(acc[0]), "+r"(acc[1])
                : "r"(*a[i + 1]), "r"(*b[i + 1]));
            final_sub(acc[1]);
        }

        uint32_t red;
        asm("mul.lo.u32 %0, %1, %2;" : "=r"(red) : "r"(acc[0]), "r"(M));
        asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
            : "+r"(acc[0]), "+r"(acc[1])
            : "r"(red), "r"(MOD));
        final_sub(acc[1]);

        return acc[1];
    }

    template <size_t T>
    static inline kb31_t
    dot_product(kb31_t a0, kb31_t b0, const kb31_t a[T - 1], const kb31_t* b, size_t stride_b = 1) {
        uint32_t acc[2];
        size_t i = 0;

        asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"
            : "=r"(acc[0]), "=r"(acc[1])
            : "r"(*a0), "r"(*b0));
        if ((T & 1) == 0) {
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
                : "+r"(acc[0]), "+r"(acc[1])
                : "r"(*a[i]), "r"(*b[0]));
            i++, b += stride_b;
        }
        for (; i < T - 1; i += 2) {
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
                : "+r"(acc[0]), "+r"(acc[1])
                : "r"(*a[i]), "r"(*b[0]));
            b += stride_b;
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
                : "+r"(acc[0]), "+r"(acc[1])
                : "r"(*a[i + 1]), "r"(*b[0]));
            b += stride_b;
            final_sub(acc[1]);
        }

        uint32_t red;
        asm("mul.lo.u32 %0, %1, %2;" : "=r"(red) : "r"(acc[0]), "r"(M));
        asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %1;"
            : "+r"(acc[0]), "+r"(acc[1])
            : "r"(red), "r"(MOD));
        final_sub(acc[1]);

        return acc[1];
    }

  private:
    static inline kb31_t sqr_n(kb31_t s, uint32_t n) {
#if 0
#pragma unroll 2
        while (n--)
            s.sqr();
#else // +20% [for reciprocal()]
#pragma unroll 2
        while (n--) {
            uint32_t tmp[2], red;

            asm("mul.lo.u32 %0, %2, %2; mul.hi.u32 %1, %2, %2;"
                : "=r"(tmp[0]), "=r"(tmp[1])
                : "r"(s.val));
            asm("mul.lo.u32 %0, %1, %2;" : "=r"(red) : "r"(tmp[0]), "r"(M));
            asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %4;"
                : "+r"(tmp[0]), "=r"(s.val)
                : "r"(red), "r"(MOD), "r"(tmp[1]));

            // if (n & 1)
            final_sub(s.val);
        }
#endif
        return s;
    }

    static inline kb31_t sqr_n_mul(kb31_t s, uint32_t n, kb31_t m) {
        s = sqr_n(s, n);
        s.mul(m);

        return s;
    }

  public:
    inline kb31_t reciprocal() const {
        kb31_t p1 = *this;
        kb31_t p10 = sqr_n(p1, 1);
        kb31_t p11 = p10 * p1;
        kb31_t p1100 = sqr_n(p11, 2);
        kb31_t p1111 = p1100 * p11;
        kb31_t p110000 = sqr_n(p1100, 2);
        kb31_t p111111 = p110000 * p1111;
        kb31_t p1111110000 = sqr_n(p111111, 4);
        kb31_t p1111111111 = p1111110000 * p1111;
        kb31_t p11111101111 = p1111111111 * p1111110000;
        kb31_t p111111011110000000000 = sqr_n(p11111101111, 10);
        kb31_t p111111011111111111111 = p111111011110000000000 * p1111111111;
        kb31_t p1111110111111111111110000000000 = sqr_n(p111111011111111111111, 10);
        kb31_t p1111110111111111111111111111111 = p1111110111111111111110000000000 * p1111111111;

        return p1111110111111111111111111111111;
    }

    friend inline kb31_t operator/(int one, kb31_t a) {
        if (one != 1)
            asm("trap;");
        return a.reciprocal();
    }

    friend inline kb31_t operator/(kb31_t a, kb31_t b) { return a * b.reciprocal(); }

    inline kb31_t& operator/=(const kb31_t a) { return *this *= a.reciprocal(); }

    inline void shfl_bfly(uint32_t laneMask) { val = __shfl_xor_sync(0xFFFFFFFF, val, laneMask); }

    __device__ __forceinline__ kb31_t interpolateLinear(const kb31_t one, const kb31_t zero) const {
        uint64_t w;
        uint32_t l = zero.val, h = 0, t;

        pack(w, l, h);

        sub(t, one.val, l);
        t = t > one.val ? t + MOD : t;

        mad_wide(w, t, val, w);
        unpack(l, h, w);

        mul_lo(t, l, M);
        mad_wide(w, t, MOD, w);
        unpack(l, h, w);

        h = h >= MOD ? h - MOD : h;

        kb31_t retval;
        retval.val = h;
        return retval;
    }
};

__device__ __forceinline__ kb31_t::accel_t& kb31_t::accel_t::operator+=(const kb31_t& b) {
    val = val >= MOD ? val + b.val - MOD : val + b.val;
    return *this;
}

__device__ __forceinline__ kb31_t::accel_t& kb31_t::accel_t::operator-=(const kb31_t& b) {
    val = val < MOD ? val - b.val + MOD : val - b.val;
    return *this;
}

__device__ __forceinline__ kb31_t::accel_t kb31_t::accel_t::operator*(const kb31_t& b) const {
    kb31_t t(*this);
    return t * b;
}

__device__ __forceinline__ kb31_t::accel_t& kb31_t::accel_t::operator*=(const kb31_t& b) {
    kb31_t t(*this);
    return *this = t * b;
}

__device__ __forceinline__ kb31_t::accel_t kb31_t::accel_t::operator+(const kb31_t& b) const {
    accel_t t(*this);
    t += b;
    return t;
}

__device__ __forceinline__ kb31_t::accel_t kb31_t::accel_t::operator-(const kb31_t& b) const {
    accel_t t(*this);
    t -= b;
    return t;
}

__device__ __forceinline__ kb31_t::accel_t& kb31_t::accel_t::operator+=(const accel_t& b) {
    val = val >= ((uint64_t)MOD << 32) ? val + b.val - ((uint64_t)MOD << 32) : val + b.val;
    return *this;
}

__device__ __forceinline__ kb31_t::accel_t& kb31_t::accel_t::operator-=(const accel_t& b) {
    val = val < ((uint64_t)MOD << 32) ? val - b.val + ((uint64_t)MOD << 32) : val - b.val;
    return *this;
}

__device__ __forceinline__ kb31_t::accel_t kb31_t::accel_t::operator+(const accel_t& b) const {
    accel_t t(*this);
    t += b;
    return t;
}

__device__ __forceinline__ kb31_t::accel_t kb31_t::accel_t::operator-(const accel_t& b) const {
    accel_t t(*this);
    t -= b;
    return t;
}

#undef inline
#undef asm
// # endif // __CUDA__ARCH__

#else

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

class kb31_t {
  private:
    static const uint32_t M = 0x77ffffffu;
    static const uint32_t RR = 0x45dddde3u;
    static const uint32_t ONE = 0x0ffffffeu;
    static const uint32_t MONTY_BITS = 32;
    static const uint32_t MONTY_MU = 0x88000001;
    static const uint32_t MONTY_MASK = ((1ULL << MONTY_BITS) - 1);

  public:
    using mem_t = kb31_t;
    uint32_t val;
    static const uint32_t DEGREE = 1;
    static const uint32_t NBITS = 31;
    static const uint32_t MOD = 0x7f000001;

    inline constexpr kb31_t() : val(0) {}

    inline constexpr kb31_t(uint32_t a) : val(a) {}

    inline constexpr kb31_t(int a) : val(((uint64_t)a << 32) % MOD) {}

    static inline const kb31_t zero() { return kb31_t(0); }

    static inline const kb31_t one() { return kb31_t(ONE); }

    static inline const kb31_t two() { return kb31_t(to_monty(2)); }

    static inline constexpr uint32_t to_monty(uint32_t x) {
        return (((uint64_t)x << MONTY_BITS) % MOD);
    }

    static inline uint32_t from_monty(uint32_t x) { return monty_reduce((uint64_t)x); }

    static inline uint32_t monty_reduce(uint64_t x) {
        uint64_t t = (x * (uint64_t)MONTY_MU) & (uint64_t)MONTY_MASK;
        uint64_t u = t * (uint64_t)MOD;
        uint64_t x_sub_u = x - u;
        bool over = x < u;
        uint32_t x_sub_u_hi = (uint32_t)(x_sub_u >> MONTY_BITS);
        uint32_t corr = over ? MOD : 0;
        return x_sub_u_hi + corr;
    }

    static inline kb31_t from_canonical_u32(uint32_t x) {
        assert(x < MOD);
        return kb31_t(to_monty(x));
    }

    static inline kb31_t from_canonical_u16(uint16_t x) { return from_canonical_u32((uint32_t)x); }

    static inline kb31_t from_canonical_u8(uint8_t x) { return from_canonical_u32((uint32_t)x); }

    static inline kb31_t from_bool(bool x) { return kb31_t(x * one().val); }

    inline uint32_t as_canonical_u32() const { return from_monty(val); }

    inline kb31_t& operator+=(kb31_t b) {
        val += b.val;
        if (val >= MOD)
            val -= MOD;
        return *this;
    }

    inline kb31_t& operator-=(kb31_t b) {
        if (val < b.val)
            val += MOD;
        val -= b.val;
        return *this;
    }

    inline kb31_t& operator*=(kb31_t b) {
        uint64_t long_prod = (uint64_t)val * (uint64_t)b.val;
        val = monty_reduce(long_prod);
        return *this;
    }

    inline kb31_t square() { return *this * *this; }

    friend kb31_t operator+(kb31_t a, kb31_t b) { return a += b; }

    friend kb31_t operator-(kb31_t a, kb31_t b) { return a -= b; }

    inline kb31_t operator-() const { return kb31_t::zero() - *this; }

    friend kb31_t operator*(kb31_t a, kb31_t b) { return a *= b; }

    inline kb31_t& operator<<=(uint32_t l) {
        while (l--) {
            val <<= 1;
            if (val >= MOD)
                val -= MOD;
        }

        return *this;
    }

    friend inline kb31_t operator<<(kb31_t a, uint32_t l) { return a <<= l; }

    inline kb31_t& operator>>=(uint32_t r) {
        while (r--) {
            val += val & 1 ? MOD : 0;
            val >>= 1;
        }

        return *this;
    }

    inline kb31_t exp_power_of_2(uint32_t power_log) const {
        kb31_t result = *this;
        for (uint32_t i = 0; i < power_log; ++i) {
            result = result.square();
        }
        return result;
    }

    inline kb31_t reciprocal() const {
        kb31_t p1 = *this;
        kb31_t p10 = sqr_n(p1, 1);
        kb31_t p11 = p10 * p1;
        kb31_t p1100 = sqr_n(p11, 2);
        kb31_t p1111 = p1100 * p11;
        kb31_t p110000 = sqr_n(p1100, 2);
        kb31_t p111111 = p110000 * p1111;
        kb31_t p1111110000 = sqr_n(p111111, 4);
        kb31_t p1111111111 = p1111110000 * p1111;
        kb31_t p11111101111 = p1111111111 * p1111110000;
        kb31_t p111111011110000000000 = sqr_n(p11111101111, 10);
        kb31_t p111111011111111111111 = p111111011110000000000 * p1111111111;
        kb31_t p1111110111111111111110000000000 = sqr_n(p111111011111111111111, 10);
        kb31_t p1111110111111111111111111111111 = p1111110111111111111110000000000 * p1111111111;

        return p1111110111111111111111111111111;
    }

    static inline kb31_t sqr_n(kb31_t s, uint32_t n) {
        while (n--)
            s.sqr();
        return s;
    }

    static inline kb31_t load(kb31_t* ptr, int i) { return ptr[i]; }

    static inline const kb31_t load(const kb31_t* ptr, int i) { return ptr[i]; }

    static inline void store(kb31_t* ptr, size_t i, kb31_t value) { ptr[i] = value; }

    inline bool operator==(const kb31_t rhs) const { return val == rhs.val; }

    inline bool operator!=(const kb31_t rhs) const { return val != rhs.val; }

    inline kb31_t& operator^=(int b) {
        kb31_t sqr = *this;
        if ((b & 1) == 0)
            *this = one();
        while (b >>= 1) {
            sqr = sqr.square();
            if (b & 1)
                *this *= sqr;
        }
        return *this;
    }

    friend kb31_t operator^(kb31_t a, uint32_t b) { return a ^= b; }

    inline kb31_t& sqr() { return *this; }

    inline void set_to_zero() { val = 0; }

    inline bool is_zero() const { return val == 0; }
};

#endif // __CUDA__ARCH__
