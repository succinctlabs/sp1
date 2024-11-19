#pragma once

#include "prelude.hpp"
#include "sp1_core_machine_sys-cbindgen.hpp"

namespace sp1 {
struct BabyBear {
    /// The value of the BabyBear field element in Montgomery form.
    BabyBearP3 val;

    static const uint32_t MOD = 0x78000001u;
    static const uint32_t MONTY_BITS = 32;
    static const uint32_t MONTY_MU = 0x88000001;
    static const uint32_t MONTY_MASK = ((1ULL << MONTY_BITS) - 1);

    __SP1_INLINE__ BabyBear() {}

    __SP1_INLINE__ BabyBear(BabyBearP3 a) : val(a) {}

    __SP1_INLINE__ constexpr BabyBear(int a) : val(((uint64_t)a << MONTY_BITS) % MOD) {}

    /// Returns a BabyBear field element representing zero.
    static BabyBear zero();

    /// Returns a BabyBear field element representing one.
    static BabyBear one();

    /// Returns a BabyBear field element representing two.
    static BabyBear two();

    /// Converts a canonical uint32_t value to a BabyBear field element.
    static BabyBear from_canonical_u32(uint32_t n);

    /// Converts a canonical uint16_t value to a BabyBear field element.
    static BabyBear from_canonical_u16(uint16_t n);

    /// Converts a canonical uint8_t value to a BabyBear field element.
    static BabyBear from_canonical_u8(uint8_t n);

    /// Converts a boolean value to a BabyBear field element.
    static BabyBear from_bool(bool b);

    /// Squares a BabyBear field element.
    BabyBear square() const;

    /// Raises a BabyBear field element to a power of 2.
    BabyBear exp_power_of_2(uintptr_t power) const;

    /// Interprets a BabyBear field element as a canonical u32 value.
    uint32_t as_canonical_u32() const;

    /// Add two BabyBear field elements.
    BabyBear& operator+=(const BabyBear b);

    friend __SP1_INLINE__ BabyBear operator+(BabyBear a, const BabyBear b) {
        return a += b;
    }

    /// Subtract two BabyBear field elements.
    BabyBear& operator-=(const BabyBear b);

    friend __SP1_INLINE__ BabyBear operator-(BabyBear a, const BabyBear b) {
        return a -= b;
    }

    /// Multiplies two BabyBear field elements together using Montgomery multiplication.
    BabyBear& operator*=(const BabyBear b);

    friend __SP1_INLINE__ BabyBear operator*(BabyBear a, const BabyBear b) {
        return a *= b;
    }

    /// Inverts a BabyBear field element using the BabyStep-GiantStep algorithm.
    BabyBear reciprocal() const;

    /// Divides one BabyBear field element by another.
    friend __SP1_INLINE__ BabyBear operator/(BabyBear a, BabyBear b) {
        return a * b.reciprocal();
    }

    __SP1_INLINE__ BabyBear& operator/=(const BabyBear a) {
        return *this *= a.reciprocal();
    }

    BabyBear& operator^=(int b);

    friend __SP1_INLINE__ BabyBear operator^(BabyBear a, uint32_t b) {
        return a ^= b;
    }

    /// Checks if two BabyBear field elements are equal.
    bool operator==(const BabyBear rhs) const;

    /// Left shifts a BabyBear field element by a given number of bits.
    __SP1_INLINE__ BabyBear& operator<<=(uint32_t l) {
        while (l--) {
            val <<= 1;
            if (val >= MOD)
                val -= MOD;
        }

        return *this;
    }

    /// Left shifts a BabyBear field element by a given number of bits.
    friend __SP1_INLINE__ BabyBear operator<<(BabyBear a, uint32_t l) {
        return a <<= l;
    }

    /// Converts a uint32_t value to a BabyBearP3 value in Montgomery form.
    static BabyBearP3 to_monty(uint32_t x);

    /// Converts a BabyBearP3 value to a uint32_t value.
    static uint32_t from_monty(BabyBearP3 x);

    /// Reduces a uint64_t value modulo the BabyBear field modulus.
    static uint32_t monty_reduce(uint64_t x);
};
}  // namespace sp1
