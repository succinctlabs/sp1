// Modified by Succinct Labs
// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cassert>
#include <cstdint>

#ifdef __CUDA_ARCH__

#define inline __device__ __forceinline__
#ifdef __GNUC__
#define asm __asm__ __volatile__
#else
#define asm asm volatile
#endif

class bb31_t {
 public:
  using mem_t = bb31_t;
  uint32_t val;
  static const uint32_t DEGREE = 1;
  static const uint32_t NBITS = 31;
  static const uint32_t MOD = 0x78000001u;
  static const uint32_t M = 0x77ffffffu;
  static const uint32_t RR = 0x45dddde3u;
  static const uint32_t ONE = 0x0ffffffeu;
  static const uint32_t MONTY_BITS = 32;
  static const uint32_t MONTY_MU = 0x88000001;
  static const uint32_t MONTY_MASK = ((1ULL << MONTY_BITS) - 1);

  static constexpr size_t __device__ bit_length() { return 31; }

  inline uint32_t& operator[](size_t i) { return val; }

  inline uint32_t& operator*() { return val; }

  inline const uint32_t& operator[](size_t i) const { return val; }

  inline uint32_t operator*() const { return val; }

  inline size_t len() const { return 1; }

  inline bb31_t() {}

  inline constexpr bb31_t(const uint32_t a) { val = a; }

  inline bb31_t(const uint32_t* p) { val = *p; }

  inline constexpr bb31_t(int a) : val(((uint64_t)a << 32) % MOD) {}

  static inline const bb31_t zero() { return bb31_t(0); }

  static inline const bb31_t one() { return bb31_t(ONE); }

  static inline const bb31_t two() { return from_canonical_u32(2); }

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

  static inline uint32_t from_monty(uint32_t x) {
    return monty_reduce((uint64_t)x);
  }

  static inline bb31_t from_canonical_u32(uint32_t x) {
    return bb31_t(to_monty(x));
  }

  static inline bb31_t from_canonical_u16(uint16_t x) {
    return from_canonical_u32((uint32_t)x);
  }

  static inline bb31_t from_canonical_u8(uint8_t x) {
    return from_canonical_u32((uint32_t)x);
  }

  static inline bb31_t from_bool(bool x) { return bb31_t(x * one().val); }

  inline uint32_t as_canonical_u32() const {
    return monty_reduce((uint64_t)val);
  }

  inline bb31_t exp_power_of_two(size_t log_power) {
    bb31_t ret = *this;
    for (size_t i = 0; i < log_power; i++) {
      ret *= ret;
    }
    return ret;
  }

  inline bb31_t& operator+=(const bb31_t b) {
    val += b.val;
    final_sub(val);

    return *this;
  }

  friend inline bb31_t operator+(bb31_t a, const bb31_t b) { return a += b; }

  inline bb31_t& operator<<=(uint32_t l) {
    while (l--) {
      val <<= 1;
      final_sub(val);
    }

    return *this;
  }

  friend inline bb31_t operator<<(bb31_t a, uint32_t l) { return a <<= l; }

  inline bb31_t& operator>>=(uint32_t r) {
    while (r--) {
      val += val & 1 ? MOD : 0;
      val >>= 1;
    }

    return *this;
  }

  friend inline bb31_t operator>>(bb31_t a, uint32_t r) { return a >>= r; }

  inline bb31_t& operator-=(const bb31_t b) {
    asm("{");
    asm(".reg.pred %brw;");
    asm("setp.lt.u32 %brw, %0, %1;" ::"r"(val), "r"(b.val));
    asm("sub.u32 %0, %0, %1;" : "+r"(val) : "r"(b.val));
    asm("@%brw add.u32 %0, %0, %1;" : "+r"(val) : "r"(MOD));
    asm("}");

    return *this;
  }

  friend inline bb31_t operator-(bb31_t a, const bb31_t b) { return a -= b; }

  inline bb31_t cneg(bool flag) {
    asm("{");
    asm(".reg.pred %flag;");
    asm("setp.ne.u32 %flag, %0, 0;" ::"r"(val));
    asm("@%flag setp.ne.u32 %flag, %0, 0;" ::"r"((int)flag));
    asm("@%flag sub.u32 %0, %1, %0;" : "+r"(val) : "r"(MOD));
    asm("}");

    return *this;
  }

  static inline bb31_t cneg(bb31_t a, bool flag) { return a.cneg(flag); }

  inline bb31_t operator-() const { return cneg(*this, true); }

  inline bool operator==(const bb31_t rhs) const { return val == rhs.val; }

  inline bool is_one() const { return val == ONE; }

  inline bool is_zero() const { return val == 0; }

  inline void set_to_zero() { val = 0; }

  friend inline bb31_t czero(const bb31_t a, int set_z) {
    bb31_t ret;

    asm("{");
    asm(".reg.pred %set_z;");
    asm("setp.ne.s32 %set_z, %0, 0;" : : "r"(set_z));
    asm("selp.u32 %0, 0, %1, %set_z;" : "=r"(ret.val) : "r"(a.val));
    asm("}");

    return ret;
  }

  static inline bb31_t csel(const bb31_t a, const bb31_t b, int sel_a) {
    bb31_t ret;

    asm("{");
    asm(".reg.pred %sel_a;");
    asm("setp.ne.s32 %sel_a, %0, 0;" ::"r"(sel_a));
    asm("selp.u32 %0, %1, %2, %sel_a;"
        : "=r"(ret.val)
        : "r"(a.val), "r"(b.val));
    asm("}");

    return ret;
  }

 private:
  static inline void final_sub(uint32_t& val) {
    asm("{");
    asm(".reg.pred %p;");
    asm("setp.ge.u32 %p, %0, %1;" ::"r"(val), "r"(MOD));
    asm("@%p sub.u32 %0, %0, %1;" : "+r"(val) : "r"(MOD));
    asm("}");
  }

  inline bb31_t& mul(const bb31_t b) {
    uint32_t tmp[2], red;

    asm("mul.lo.u32 %0, %2, %3; mul.hi.u32 %1, %2, %3;"
        : "=r"(tmp[0]), "=r"(tmp[1])
        : "r"(val), "r"(b.val));
    asm("mul.lo.u32 %0, %1, %2;" : "=r"(red) : "r"(tmp[0]), "r"(M));
    asm("mad.lo.cc.u32 %0, %2, %3, %0; madc.hi.u32 %1, %2, %3, %4;"
        : "+r"(tmp[0]), "=r"(val)
        : "r"(red), "r"(MOD), "r"(tmp[1]));

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
  friend inline bb31_t operator*(bb31_t a, const bb31_t b) { return a.mul(b); }

  inline bb31_t& operator*=(const bb31_t a) { return mul(a); }

  // raise to a variable power, variable in respect to threadIdx,
  // but mind the ^ operator's precedence!
  inline bb31_t& operator^=(uint32_t p) {
    bb31_t sqr = *this;
    *this = csel(val, ONE, p & 1);

#pragma unroll 1
    while (p >>= 1) {
      sqr.mul(sqr);
      if (p & 1)
        mul(sqr);
    }

    return *this;
  }

  friend inline bb31_t operator^(bb31_t a, uint32_t p) { return a ^= p; }

  inline bb31_t operator()(uint32_t p) { return *this ^ p; }

  // raise to a constant power, e.g. x^7, to be unrolled at compile time
  inline bb31_t& operator^=(int p) {
    if (p < 2)
      asm("trap;");

    bb31_t sqr = *this;
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

  friend inline bb31_t operator^(bb31_t a, int p) { return a ^= p; }

  inline bb31_t operator()(int p) { return *this ^ p; }

  inline bb31_t square() { return *this * *this; }

  friend inline bb31_t sqr(bb31_t a) { return a.sqr(); }

  inline bb31_t& sqr() { return mul(*this); }

  inline void to() { mul(RR); }

  inline void from() { val = mul_by_1(); }

  template <size_t T>
  static inline bb31_t dot_product(const bb31_t a[T], const bb31_t b[T]) {
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
  static inline bb31_t dot_product(bb31_t a0, bb31_t b0, const bb31_t a[T - 1],
                                   const bb31_t* b, size_t stride_b = 1) {
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
  static inline bb31_t sqr_n(bb31_t s, uint32_t n) {
#if 0
#pragma unroll 2
        while (n--)
            s.sqr();
#else  // +20% [for reciprocal()]
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

      if (n & 1)
        final_sub(s.val);
    }
#endif
    return s;
  }

  static inline bb31_t sqr_n_mul(bb31_t s, uint32_t n, bb31_t m) {
    s = sqr_n(s, n);
    s.mul(m);

    return s;
  }

 public:
  inline bb31_t reciprocal() const {
    bb31_t x11, xff, ret = *this;

    x11 = sqr_n_mul(ret, 4, ret);  // 0b10001
    ret = sqr_n_mul(x11, 1, x11);  // 0b110011
    ret = sqr_n_mul(ret, 1, x11);  // 0b1110111
    xff = sqr_n_mul(ret, 1, x11);  // 0b11111111
    ret = sqr_n_mul(ret, 8, xff);  // 0b111011111111111
    ret = sqr_n_mul(ret, 8, xff);  // 0b11101111111111111111111
    ret = sqr_n_mul(ret, 8, xff);  // 0b1110111111111111111111111111111

    return ret;
  }

  friend inline bb31_t operator/(int one, bb31_t a) {
    if (one != 1)
      asm("trap;");
    return a.reciprocal();
  }

  friend inline bb31_t operator/(bb31_t a, bb31_t b) {
    return a * b.reciprocal();
  }

  inline bb31_t& operator/=(const bb31_t a) { return *this *= a.reciprocal(); }

  inline bb31_t heptaroot() const {
    bb31_t x03, x18, x1b, ret = *this;

    x03 = sqr_n_mul(ret, 1, ret);    // 0b11
    x18 = sqr_n(x03, 3);             // 0b11000
    x1b = x18 * x03;                 // 0b11011
    ret = x18 * x1b;                 // 0b110011
    ret = sqr_n_mul(ret, 6, x1b);    // 0b110011011011
    ret = sqr_n_mul(ret, 6, x1b);    // 0b110011011011011011
    ret = sqr_n_mul(ret, 6, x1b);    // 0b110011011011011011011011
    ret = sqr_n_mul(ret, 6, x1b);    // 0b110011011011011011011011011011
    ret = sqr_n_mul(ret, 1, *this);  // 0b1100110110110110110110110110111

    return ret;
  }

  inline void shfl_bfly(uint32_t laneMask) {
    val = __shfl_xor_sync(0xFFFFFFFF, val, laneMask);
  }
};

#undef inline
#undef asm
// # endif // __CUDA__ARCH__

#else

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

class bb31_t {
 private:
  static const uint32_t M = 0x77ffffffu;
  static const uint32_t RR = 0x45dddde3u;
  static const uint32_t ONE = 0x0ffffffeu;
  static const uint32_t MONTY_BITS = 32;
  static const uint32_t MONTY_MU = 0x88000001;
  static const uint32_t MONTY_MASK = ((1ULL << MONTY_BITS) - 1);

 public:
  using mem_t = bb31_t;
  uint32_t val;
  static const uint32_t DEGREE = 1;
  static const uint32_t NBITS = 31;
  static const uint32_t MOD = 0x78000001;

  inline constexpr bb31_t() : val(0) {}

  inline constexpr bb31_t(uint32_t a) : val(a) {}

  inline constexpr bb31_t(int a) : val(((uint64_t)a << 32) % MOD) {}

  static inline const bb31_t zero() { return bb31_t(0); }

  static inline const bb31_t one() { return bb31_t(ONE); }

  static inline const bb31_t two() { return bb31_t(to_monty(2)); }

  static inline constexpr uint32_t to_monty(uint32_t x) {
    return (((uint64_t)x << MONTY_BITS) % MOD);
  }

  static inline uint32_t from_monty(uint32_t x) {
    return monty_reduce((uint64_t)x);
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

  static inline bb31_t from_canonical_u32(uint32_t x) {
    assert(x < MOD);
    return bb31_t(to_monty(x));
  }

  static inline bb31_t from_canonical_u16(uint16_t x) {
    return from_canonical_u32((uint32_t)x);
  }

  static inline bb31_t from_canonical_u8(uint8_t x) {
    return from_canonical_u32((uint32_t)x);
  }

  static inline bb31_t from_bool(bool x) { return bb31_t(x * one().val); }

  inline uint32_t as_canonical_u32() const { return from_monty(val); }

  inline bb31_t& operator+=(bb31_t b) {
    val += b.val;
    if (val >= MOD)
      val -= MOD;
    return *this;
  }

  inline bb31_t& operator-=(bb31_t b) {
    if (val < b.val)
      val += MOD;
    val -= b.val;
    return *this;
  }

  inline bb31_t& operator*=(bb31_t b) {
    uint64_t long_prod = (uint64_t)val * (uint64_t)b.val;
    val = monty_reduce(long_prod);
    return *this;
  }

  inline bb31_t square() { return *this * *this; }

  friend bb31_t operator+(bb31_t a, bb31_t b) { return a += b; }

  friend bb31_t operator-(bb31_t a, bb31_t b) { return a -= b; }

  friend bb31_t operator*(bb31_t a, bb31_t b) { return a *= b; }

  inline bb31_t& operator<<=(uint32_t l) {
    while (l--) {
      val <<= 1;
      if (val >= MOD)
        val -= MOD;
    }

    return *this;
  }

  friend inline bb31_t operator<<(bb31_t a, uint32_t l) { return a <<= l; }

  inline bb31_t& operator>>=(uint32_t r) {
    while (r--) {
      val += val & 1 ? MOD : 0;
      val >>= 1;
    }

    return *this;
  }

  inline bb31_t exp_power_of_2(uint32_t power_log) const {
    bb31_t result = *this;
    for (uint32_t i = 0; i < power_log; ++i) {
      result = result.square();
    }
    return result;
  }

  inline bb31_t reciprocal() const {
    assert(*this != zero());

    bb31_t p1 = *this;
    bb31_t p100000000 = p1.exp_power_of_2(8);
    bb31_t p100000001 = p100000000 * p1;
    bb31_t p10000000000000000 = p100000000.exp_power_of_2(8);
    bb31_t p10000000100000001 = p10000000000000000 * p100000001;
    bb31_t p10000000100000001000 = p10000000100000001.exp_power_of_2(3);
    bb31_t p1000000010000000100000000 = p10000000100000001000.exp_power_of_2(5);
    bb31_t p1000000010000000100000001 = p1000000010000000100000000 * p1;
    bb31_t p1000010010000100100001001 =
        p1000000010000000100000001 * p10000000100000001000;
    bb31_t p10000000100000001000000010 = p1000000010000000100000001.square();
    bb31_t p11000010110000101100001011 =
        p10000000100000001000000010 * p1000010010000100100001001;
    bb31_t p100000001000000010000000100 = p10000000100000001000000010.square();
    bb31_t p111000011110000111100001111 =
        p100000001000000010000000100 * p11000010110000101100001011;
    bb31_t p1110000111100001111000011110000 =
        p111000011110000111100001111.exp_power_of_2(4);
    bb31_t p1110111111111111111111111111111 =
        p1110000111100001111000011110000 * p111000011110000111100001111;

    return p1110111111111111111111111111111;
  }

  inline bool operator==(const bb31_t rhs) const { return val == rhs.val; }

  inline bool operator!=(const bb31_t rhs) const { return !(*this == rhs); }

  inline bb31_t& operator^=(int b) {
    bb31_t sqr = *this;
    if ((b & 1) == 0)
      *this = one();
    while (b >>= 1) {
      sqr = sqr.square();
      if (b & 1)
        *this *= sqr;
    }
    return *this;
  }

  friend bb31_t operator^(bb31_t a, uint32_t b) { return a ^= b; }

  inline bb31_t& sqr() { return *this; }

  inline void set_to_zero() { val = 0; }

  inline bool is_zero() const { return val == 0; }
};

#endif  // __CUDA__ARCH__