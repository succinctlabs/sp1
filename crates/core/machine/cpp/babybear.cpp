#include "babybear.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>

using namespace sp1_core_machine_sys;

/// Returns a BabyBear field element representing zero.
BabyBear BabyBear::zero() {
    return BabyBear::from_canonical_u32(0);
}

/// Returns a BabyBear field element representing one.
BabyBear BabyBear::one() {
    return BabyBear::from_canonical_u32(1);
}

/// Returns a BabyBear field element representing two.
BabyBear BabyBear::two() {
    return BabyBear::from_canonical_u32(2);
}

/// Converts a canonical uint32_t value to a BabyBear field element.
BabyBear BabyBear::from_canonical_u32(uint32_t n) {
    assert(n < MOD);
    return BabyBear(to_monty(n));
}

/// Converts a canonical uint16_t value to a BabyBear field element.
BabyBear BabyBear::from_canonical_u16(uint16_t n) {
    return from_canonical_u32((uint32_t)n);
}

/// Converts a canonical uint8_t value to a BabyBear field element.
BabyBear BabyBear::from_canonical_u8(uint8_t n) {
    return from_canonical_u32((uint32_t)n);
}

/// Converts a boolean value to a BabyBear field element.
BabyBear BabyBear::from_bool(bool b) {
    return BabyBear(b * BabyBear::one().val);
}

/// Squares a BabyBear element.
BabyBear BabyBear::square() const {
    return *this * *this;
}

/// Raises a BabyBear element to a power of 2.
BabyBear BabyBear::exp_power_of_2(uintptr_t power_log) const {
    BabyBear result = *this;
    for (uintptr_t i = 0; i < power_log; ++i) {
        result = result.square();
    }
    return result;
}

/// Interprets a BabyBear field element as a canonical u32 value.
uint32_t BabyBear::as_canonical_u32() const {
    return from_monty(val);
}

/// Adds two BabyBear field elements together.
BabyBear& BabyBear::operator+=(const BabyBear b) {
    val += b.val;
    if (val >= MOD)
        val -= MOD;
    return *this;
}

/// Subtracts one BabyBear field element from another.
BabyBear& BabyBear::operator-=(const BabyBear b) {
    if (val < b.val)
        val += MOD;
    val -= b.val;
    return *this;
}

/// Multiplies two BabyBear field elements together using Montgomery multiplication.
BabyBear& BabyBear::operator*=(const BabyBear b) {
    uint64_t long_prod = (uint64_t)val * (uint64_t)b.val;
    val = monty_reduce(long_prod);
    return *this;
}

/// Inverts a BabyBear field element using the BabyStep-GiantStep algorithm.
BabyBear BabyBear::reciprocal() const {
    assert(*this != BabyBear::zero());

    BabyBear p1 = *this;
    BabyBear p100000000 = p1.exp_power_of_2(8);
    BabyBear p100000001 = p100000000 * p1;
    BabyBear p10000000000000000 = p100000000.exp_power_of_2(8);
    BabyBear p10000000100000001 = p10000000000000000 * p100000001;
    BabyBear p10000000100000001000 = p10000000100000001.exp_power_of_2(3);
    BabyBear p1000000010000000100000000 = p10000000100000001000.exp_power_of_2(5);
    BabyBear p1000000010000000100000001 = p1000000010000000100000000 * p1;
    BabyBear p1000010010000100100001001 = p1000000010000000100000001 * p10000000100000001000;
    BabyBear p10000000100000001000000010 = p1000000010000000100000001.square();
    BabyBear p11000010110000101100001011 = p10000000100000001000000010 * p1000010010000100100001001;
    BabyBear p100000001000000010000000100 = p10000000100000001000000010.square();
    BabyBear p111000011110000111100001111 =
        p100000001000000010000000100 * p11000010110000101100001011;
    BabyBear p1110000111100001111000011110000 = p111000011110000111100001111.exp_power_of_2(4);
    BabyBear p1110111111111111111111111111111 =
        p1110000111100001111000011110000 * p111000011110000111100001111;

    return p1110111111111111111111111111111;
}

/// Raises a BabyBear element to a power.
BabyBear& BabyBear::operator^=(int p) {
    BabyBear sqr = *this;
    if ((p & 1) == 0)
        *this = one();
    while (p >>= 1) {
        sqr = sqr.square();
        if (p & 1)
            *this *= sqr;
    }
    return *this;
}

bool BabyBear::is_square() const {
    BabyBear base = *this;
    base^=1006632960;
    return base == BabyBear::one();
}

/// Checks if two BabyBear field elements are equal.
bool BabyBear::operator==(const BabyBear rhs) const {
    return val == rhs.val;
}

/// Converts a canonical uint32_t value to a BabyBear field element in Montgomery form.
BabyBearP3 BabyBear::to_monty(uint32_t x) {
    return (((uint64_t)x << MONTY_BITS) % MOD);
}

/// Converts a BabyBear field element in Montgomery form to a canonical uint32_t value.
uint32_t BabyBear::from_monty(BabyBearP3 x) {
    return monty_reduce((uint64_t)x);
}

/// Reduces a uint64_t value modulo the BabyBear field modulus.
uint32_t BabyBear::monty_reduce(uint64_t x) {
    uint64_t t = (x * (uint64_t)MONTY_MU) & (uint64_t)MONTY_MASK;
    uint64_t u = t * (uint64_t)MOD;
    uint64_t x_sub_u = x - u;
    bool over = x < u;  // Check for overflow.
    uint32_t x_sub_u_hi = (uint32_t)(x_sub_u >> MONTY_BITS);
    uint32_t corr = over ? MOD : 0;
    return x_sub_u_hi + corr;
}