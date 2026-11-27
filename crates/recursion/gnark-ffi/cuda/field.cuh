#pragma once

// BN254 field arithmetic in Montgomery form, with the same memory layout as gnark-crypto:
// four little-endian 64-bit limbs holding x * 2^256 mod p.

#include <cstdint>

#define SP1_LIMBS(l0, l1, l2, l3, l4, l5, l6, l7)                                                       \
  __host__ __device__ static constexpr uint32_t p(int i) {                                               \
    return i == 0 ? l0 : i == 1 ? l1 : i == 2 ? l2 : i == 3 ? l3 : i == 4 ? l4 : i == 5 ? l5 : i == 6 ? l6 : l7; \
  }

struct FrParams {
  SP1_LIMBS(0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72)
  static constexpr uint32_t inv = 0xefffffff;  // -p^-1 mod 2^32
  static constexpr uint64_t one[4] = {0xac96341c4ffffffbULL, 0x36fc76959f60cd29ULL, 0x666ea36f7879462eULL,
                                      0x0e0a77c19a07df2fULL};
};

struct FpParams {
  SP1_LIMBS(0xd87cfd47, 0x3c208c16, 0x6871ca8d, 0x97816a91, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72)
  static constexpr uint32_t inv = 0xe4866389;
  static constexpr uint64_t one[4] = {0xd35d438dc58f0d9dULL, 0x0a78eb28f5c70b3dULL, 0x666ea36f7879462cULL,
                                      0x0e0a77c19a07df2fULL};
};

// Multiply-accumulates (A0, A2, A4, A6) * B into X0..X7 as lo/hi pairs in one carry chain, so that
// ptxas fuses each pair into IMAD.WIDE; the carry lands in X8 and X9.
#define SP1_MAD_PAIRS(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, A0, A2, A4, A6, B)                    \
  asm("mad.lo.cc.u32 %0, %10, %14, %0;\n\tmadc.hi.cc.u32 %1, %10, %14, %1;\n\t"                     \
      "madc.lo.cc.u32 %2, %11, %14, %2;\n\tmadc.hi.cc.u32 %3, %11, %14, %3;\n\t"                    \
      "madc.lo.cc.u32 %4, %12, %14, %4;\n\tmadc.hi.cc.u32 %5, %12, %14, %5;\n\t"                    \
      "madc.lo.cc.u32 %6, %13, %14, %6;\n\tmadc.hi.cc.u32 %7, %13, %14, %7;\n\t"                    \
      "addc.cc.u32 %8, %8, 0;\n\taddc.u32 %9, %9, 0;"                                               \
      : "+r"(X0), "+r"(X1), "+r"(X2), "+r"(X3), "+r"(X4), "+r"(X5), "+r"(X6), "+r"(X7), "+r"(X8), \
        "+r"(X9)                                                                                    \
      : "r"(A0), "r"(A2), "r"(A4), "r"(A6), "r"(B))

template <class P>
struct Fe {
  uint64_t v[4];

  __host__ __device__ static Fe zero() { return Fe{{0, 0, 0, 0}}; }
  __host__ __device__ static Fe one() { return Fe{{P::one[0], P::one[1], P::one[2], P::one[3]}}; }

  __device__ __forceinline__ bool is_zero() const { return (v[0] | v[1] | v[2] | v[3]) == 0; }
  __device__ __forceinline__ bool operator==(const Fe& o) const {
    return v[0] == o.v[0] && v[1] == o.v[1] && v[2] == o.v[2] && v[3] == o.v[3];
  }

  __device__ __forceinline__ static bool geq_p(const uint32_t* t) {
#pragma unroll
    for (int i = 7; i >= 0; i--) {
      if (t[i] != P::p(i)) return t[i] > P::p(i);
    }
    return true;
  }

  __device__ __forceinline__ static void sub_p(uint32_t* t) {
    asm("sub.cc.u32 %0, %0, %8;\n\tsubc.cc.u32 %1, %1, %9;\n\tsubc.cc.u32 %2, %2, %10;\n\t"
        "subc.cc.u32 %3, %3, %11;\n\tsubc.cc.u32 %4, %4, %12;\n\tsubc.cc.u32 %5, %5, %13;\n\t"
        "subc.cc.u32 %6, %6, %14;\n\tsubc.u32 %7, %7, %15;"
        : "+r"(t[0]), "+r"(t[1]), "+r"(t[2]), "+r"(t[3]), "+r"(t[4]), "+r"(t[5]), "+r"(t[6]), "+r"(t[7])
        : "n"(P::p(0)), "n"(P::p(1)), "n"(P::p(2)), "n"(P::p(3)), "n"(P::p(4)), "n"(P::p(5)), "n"(P::p(6)),
          "n"(P::p(7)));
  }

  __device__ __forceinline__ Fe operator+(const Fe& b) const {
    Fe r;
    uint32_t* t = reinterpret_cast<uint32_t*>(r.v);
    const uint32_t* x = reinterpret_cast<const uint32_t*>(v);
    const uint32_t* y = reinterpret_cast<const uint32_t*>(b.v);
    asm("add.cc.u32 %0, %8, %16;\n\taddc.cc.u32 %1, %9, %17;\n\taddc.cc.u32 %2, %10, %18;\n\t"
        "addc.cc.u32 %3, %11, %19;\n\taddc.cc.u32 %4, %12, %20;\n\taddc.cc.u32 %5, %13, %21;\n\t"
        "addc.cc.u32 %6, %14, %22;\n\taddc.u32 %7, %15, %23;"
        : "=r"(t[0]), "=r"(t[1]), "=r"(t[2]), "=r"(t[3]), "=r"(t[4]), "=r"(t[5]), "=r"(t[6]), "=r"(t[7])
        : "r"(x[0]), "r"(x[1]), "r"(x[2]), "r"(x[3]), "r"(x[4]), "r"(x[5]), "r"(x[6]), "r"(x[7]), "r"(y[0]),
          "r"(y[1]), "r"(y[2]), "r"(y[3]), "r"(y[4]), "r"(y[5]), "r"(y[6]), "r"(y[7]));
    if (geq_p(t)) sub_p(t);
    return r;
  }

  __device__ __forceinline__ Fe operator-(const Fe& b) const {
    Fe r;
    uint32_t* t = reinterpret_cast<uint32_t*>(r.v);
    const uint32_t* x = reinterpret_cast<const uint32_t*>(v);
    const uint32_t* y = reinterpret_cast<const uint32_t*>(b.v);
    uint32_t borrow;
    asm("sub.cc.u32 %0, %9, %17;\n\tsubc.cc.u32 %1, %10, %18;\n\tsubc.cc.u32 %2, %11, %19;\n\t"
        "subc.cc.u32 %3, %12, %20;\n\tsubc.cc.u32 %4, %13, %21;\n\tsubc.cc.u32 %5, %14, %22;\n\t"
        "subc.cc.u32 %6, %15, %23;\n\tsubc.cc.u32 %7, %16, %24;\n\tsubc.u32 %8, 0, 0;"
        : "=r"(t[0]), "=r"(t[1]), "=r"(t[2]), "=r"(t[3]), "=r"(t[4]), "=r"(t[5]), "=r"(t[6]), "=r"(t[7]),
          "=r"(borrow)
        : "r"(x[0]), "r"(x[1]), "r"(x[2]), "r"(x[3]), "r"(x[4]), "r"(x[5]), "r"(x[6]), "r"(x[7]), "r"(y[0]),
          "r"(y[1]), "r"(y[2]), "r"(y[3]), "r"(y[4]), "r"(y[5]), "r"(y[6]), "r"(y[7]));
    if (borrow) {
      asm("add.cc.u32 %0, %0, %8;\n\taddc.cc.u32 %1, %1, %9;\n\taddc.cc.u32 %2, %2, %10;\n\t"
          "addc.cc.u32 %3, %3, %11;\n\taddc.cc.u32 %4, %4, %12;\n\taddc.cc.u32 %5, %5, %13;\n\t"
          "addc.cc.u32 %6, %6, %14;\n\taddc.u32 %7, %7, %15;"
          : "+r"(t[0]), "+r"(t[1]), "+r"(t[2]), "+r"(t[3]), "+r"(t[4]), "+r"(t[5]), "+r"(t[6]), "+r"(t[7])
          : "n"(P::p(0)), "n"(P::p(1)), "n"(P::p(2)), "n"(P::p(3)), "n"(P::p(4)), "n"(P::p(5)), "n"(P::p(6)),
            "n"(P::p(7)));
    }
    return r;
  }

  __device__ __forceinline__ Fe operator-() const { return zero() - *this; }
  __device__ __forceinline__ Fe dbl() const { return *this + *this; }

  // CIOS Montgomery multiplication with the even and odd limb products kept in separate accumulators.
  __device__ __forceinline__ Fe operator*(const Fe& B) const {
    const uint32_t* a = reinterpret_cast<const uint32_t*>(v);
    const uint32_t* b = reinterpret_cast<const uint32_t*>(B.v);
    const uint32_t q0 = P::p(0), q1 = P::p(1), q2 = P::p(2), q3 = P::p(3), q4 = P::p(4), q5 = P::p(5),
                   q6 = P::p(6), q7 = P::p(7);
    uint32_t x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0, x5 = 0, x6 = 0, x7 = 0, x8 = 0, x9 = 0;
    uint32_t y0 = 0, y1 = 0, y2 = 0, y3 = 0, y4 = 0, y5 = 0, y6 = 0, y7 = 0, y8 = 0, y9 = 0, unused = 0;
#pragma unroll
    for (int i = 0; i < 8; i++) {
      uint32_t bi = b[i];
      SP1_MAD_PAIRS(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, a[0], a[2], a[4], a[6], bi);
      SP1_MAD_PAIRS(y1, y2, y3, y4, y5, y6, y7, y8, y9, unused, a[1], a[3], a[5], a[7], bi);
      uint32_t m = (x0 + y0) * P::inv;
      SP1_MAD_PAIRS(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, q0, q2, q4, q6, m);
      SP1_MAD_PAIRS(y1, y2, y3, y4, y5, y6, y7, y8, y9, unused, q1, q3, q5, q7, m);
      uint32_t low;
      asm("add.cc.u32 %0, %1, %2;\n\taddc.cc.u32 %3, %3, 0;\n\taddc.cc.u32 %4, %4, 0;\n\taddc.cc.u32 %5, %5, 0;\n\t"
          "addc.cc.u32 %6, %6, 0;\n\taddc.cc.u32 %7, %7, 0;\n\taddc.cc.u32 %8, %8, 0;\n\taddc.cc.u32 %9, %9, 0;\n\t"
          "addc.cc.u32 %10, %10, 0;\n\taddc.u32 %11, %11, 0;"
          : "=r"(low), "+r"(x0), "+r"(y0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7),
            "+r"(x8), "+r"(x9));
      x0 = x1, x1 = x2, x2 = x3, x3 = x4, x4 = x5, x5 = x6, x6 = x7, x7 = x8, x8 = x9, x9 = 0;
      y0 = y1, y1 = y2, y2 = y3, y3 = y4, y4 = y5, y5 = y6, y6 = y7, y7 = y8, y8 = y9, y9 = 0;
    }
    Fe r;
    uint32_t* t = reinterpret_cast<uint32_t*>(r.v);
    uint32_t top;
    asm("add.cc.u32 %0, %9, %18;\n\taddc.cc.u32 %1, %10, %19;\n\taddc.cc.u32 %2, %11, %20;\n\t"
        "addc.cc.u32 %3, %12, %21;\n\taddc.cc.u32 %4, %13, %22;\n\taddc.cc.u32 %5, %14, %23;\n\t"
        "addc.cc.u32 %6, %15, %24;\n\taddc.cc.u32 %7, %16, %25;\n\taddc.u32 %8, %17, %26;"
        : "=r"(t[0]), "=r"(t[1]), "=r"(t[2]), "=r"(t[3]), "=r"(t[4]), "=r"(t[5]), "=r"(t[6]), "=r"(t[7]), "=r"(top)
        : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7), "r"(x8), "r"(y0), "r"(y1),
          "r"(y2), "r"(y3), "r"(y4), "r"(y5), "r"(y6), "r"(y7), "r"(y8));
    if (top || geq_p(t)) sub_p(t);
    return r;
  }

  __device__ __forceinline__ Fe sqr() const { return *this * *this; }

  // Converts out of Montgomery form, giving the canonical integer.
  __device__ __forceinline__ Fe to_canonical() const { return *this * Fe{{1, 0, 0, 0}}; }

  __device__ Fe inverse() const {
    uint32_t e[8];
#pragma unroll
    for (int i = 0; i < 8; i++) e[i] = P::p(i);
    e[0] -= 2;
    Fe r = one();
    for (int i = 7; i >= 0; i--) {
      for (int b = 31; b >= 0; b--) {
        r = r.sqr();
        if ((e[i] >> b) & 1) r = r * *this;
      }
    }
    return r;
  }
};

using Fr = Fe<FrParams>;
using Fp = Fe<FpParams>;

// Fp2 = Fp[u] / (u^2 + 1), matching gnark-crypto's E2.
struct Fp2 {
  Fp c0, c1;

  __host__ __device__ static Fp2 zero() { return Fp2{Fp::zero(), Fp::zero()}; }
  __host__ __device__ static Fp2 one() { return Fp2{Fp::one(), Fp::zero()}; }
  __device__ __forceinline__ bool is_zero() const { return c0.is_zero() && c1.is_zero(); }
  __device__ __forceinline__ bool operator==(const Fp2& o) const { return c0 == o.c0 && c1 == o.c1; }
  __device__ __forceinline__ Fp2 operator+(const Fp2& b) const { return Fp2{c0 + b.c0, c1 + b.c1}; }
  __device__ __forceinline__ Fp2 operator-(const Fp2& b) const { return Fp2{c0 - b.c0, c1 - b.c1}; }
  __device__ __forceinline__ Fp2 operator-() const { return Fp2{-c0, -c1}; }
  __device__ __forceinline__ Fp2 dbl() const { return Fp2{c0.dbl(), c1.dbl()}; }
  __device__ __forceinline__ Fp2 operator*(const Fp2& b) const {
    Fp t0 = c0 * b.c0, t1 = c1 * b.c1;
    Fp t2 = (c0 + c1) * (b.c0 + b.c1);
    return Fp2{t0 - t1, t2 - t0 - t1};
  }
  __device__ __forceinline__ Fp2 sqr() const {
    Fp t = c0 * c1;
    return Fp2{(c0 + c1) * (c0 - c1), t.dbl()};
  }
};
