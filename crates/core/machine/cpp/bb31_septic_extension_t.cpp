#include "bb31_septic_extension_t.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>

using namespace sp1_core_machine_sys;

bb31_septic_extension_t bb31_septic_extension_t::zero() {
    return bb31_septic_extension_t(bb31_t::zero());
}

bb31_septic_extension_t bb31_septic_extension_t::one() {
    return bb31_septic_extension_t(bb31_t::one());
}

bb31_septic_extension_t bb31_septic_extension_t::two() {
    return bb31_septic_extension_t(bb31_t::two());
}

bb31_septic_extension_t bb31_septic_extension_t::from_canonical_u32(uint32_t n) {
    return bb31_septic_extension_t(bb31_t::from_canonical_u32(n));
}

bb31_septic_extension_t& bb31_septic_extension_t::operator+=(const bb31_t b) {
    value[0] += b;
    return *this;
}

bb31_septic_extension_t& bb31_septic_extension_t::operator+=(const bb31_septic_extension_t b) {
    for (uintptr_t i = 0 ; i < 7 ; i++) {
        value[i] += b.value[i];
    }
    return *this;
}

bb31_septic_extension_t& bb31_septic_extension_t::operator-=(const bb31_t b) {
    value[0] -= b;
    return *this;
}

bb31_septic_extension_t& bb31_septic_extension_t::operator-=(const bb31_septic_extension_t b) {
    for (uintptr_t i = 0 ; i < 7 ; i++) {
        value[i] -= b.value[i];
    }
    return *this;
}

bb31_septic_extension_t& bb31_septic_extension_t::operator*=(const bb31_t b) {
    for (uintptr_t i = 0 ; i < 7 ; i++) {
        value[i] *= b;
    }
    return *this;
}

bb31_septic_extension_t& bb31_septic_extension_t::operator*=(const bb31_septic_extension_t b) {
    bb31_t res[13] = {};
    for(uintptr_t i = 0 ; i < 13 ; i++) {
        res[i] = bb31_t::zero();
    }
    for(uintptr_t i = 0 ; i < 7 ; i++) {
        for(uintptr_t j = 0 ; j < 7 ; j++) {
            res[i + j] += value[i] * b.value[j];
        }
    }
    for(uintptr_t i = 7 ; i < 13 ; i++) {
        res[i - 7] += res[i] * bb31_t::from_canonical_u32(5);
        res[i - 6] += res[i] * bb31_t::from_canonical_u32(2);
    }
    for(uintptr_t i = 0 ; i < 7 ; i++) {
        value[i] = res[i];
    }
    return *this;
}

bool bb31_septic_extension_t::operator==(const bb31_septic_extension_t rhs) const {
    for(uintptr_t i = 0 ; i < 7 ; i++) {
        if(value[i] != rhs.value[i]) {
            return false;
        }
    }
    return true;
}

bb31_septic_extension_t bb31_septic_extension_t::frobenius() const {
    bb31_t res[7] = {};
    res[0] = value[0];
    for(uintptr_t i = 1 ; i < 7 ; i++) {
        res[i] = bb31_t::zero();
    }
    for(uintptr_t i = 1 ; i < 7 ; i++) {
        for(uintptr_t j = 0 ; j < 7 ; j++) {
            res[j] += value[i] * frobenius_const[i][j];
        }
    }
    return bb31_septic_extension_t(res);
}

bb31_septic_extension_t bb31_septic_extension_t::double_frobenius() const {
    bb31_t res[7] = {};
    res[0] = value[0];
    for(uintptr_t i = 1 ; i < 7 ; i++) {
        res[i] = bb31_t::zero();
    }
    for(uintptr_t i = 1 ; i < 7 ; i++) {
        for(uintptr_t j = 0 ; j < 7 ; j++) {
            res[j] += value[i] * double_frobenius_const[i][j];
        }
    }
    return bb31_septic_extension_t(res);
}

bb31_septic_extension_t bb31_septic_extension_t::pow_r_1() const {
    bb31_septic_extension_t base = frobenius();
    base *= double_frobenius();
    bb31_septic_extension_t base_p2 = base.double_frobenius();
    bb31_septic_extension_t base_p4 = base_p2.double_frobenius();
    return base * base_p2 * base_p4;
}

bb31_t bb31_septic_extension_t::pow_r() const {
    bb31_septic_extension_t pow_r1 = pow_r_1();
    bb31_septic_extension_t pow_r = pow_r1 * *this;
    for(uintptr_t i = 1 ; i < 7 ; i++) {
        assert(pow_r.value[i] == bb31_t::zero());
    }
    return pow_r.value[0];
}

bb31_septic_extension_t bb31_septic_extension_t::reciprocal() const {
    bb31_septic_extension_t pow_r_1 = this->pow_r_1();
    bb31_septic_extension_t pow_r = pow_r_1 * *this;
    return pow_r_1 * pow_r.value[0].reciprocal();
}

bb31_septic_extension_t bb31_septic_extension_t::sqrt(bb31_t pow_r) const {
    if (*this == bb31_septic_extension_t::zero()) {
        return *this;
    }

    bb31_septic_extension_t n_iter = *this;
    bb31_septic_extension_t n_power = *this;
    for(uintptr_t i = 1 ; i < 30 ; i++) {
        n_iter *= n_iter;
        if(i >= 26) {
            n_power *= n_iter;
        }
    }

    bb31_septic_extension_t n_frobenius = n_power.frobenius();
    bb31_septic_extension_t denominator = n_frobenius;

    n_frobenius = n_frobenius.double_frobenius();
    denominator *= n_frobenius;
    n_frobenius = n_frobenius.double_frobenius();
    denominator *= n_frobenius;
    denominator *= *this;

    bb31_t base = pow_r.reciprocal();
    bb31_t g = bb31_t::from_canonical_u32(31);
    bb31_t a = bb31_t::one();
    bb31_t nonresidue = bb31_t::one() - base;

    while (true) {
        bb31_t is_square = nonresidue ^ 1006632960;
        if (is_square != bb31_t::one()) {
            break;
        }
        a *= g;
        nonresidue = a.square() - base;
    }

    bb31_cipolla_t x = bb31_cipolla_t(a, bb31_t::one());
    x = x.pow(1006632961, nonresidue);

    return denominator * x.real;
}

bb31_septic_extension_t bb31_septic_extension_t::universal_hash() const {
    return *this * bb31_septic_extension_t(A_EC_LOGUP) + bb31_septic_extension_t(B_EC_LOGUP);
}

bb31_septic_extension_t bb31_septic_extension_t::curve_formula() const {
    bb31_septic_extension_t result = (*this * *this + bb31_t::two()) * *this;
    result.value[5] += bb31_t::from_canonical_u32(26);
    return result;
}

bool bb31_septic_extension_t::is_receive() const {
    uint32_t limb = value[6].as_canonical_u32();
    return 1 <= limb && limb <= (bb31_t::MOD - 1) / 2;
}

bool bb31_septic_extension_t::is_send() const {
    uint32_t limb = value[6].as_canonical_u32();
    return (bb31_t::MOD + 1) / 2 <= limb && limb <= (bb31_t::MOD - 1);
}

bool bb31_septic_extension_t::is_exception() const {
    return value[6] == bb31_t::zero();
}

bb31_cipolla_t bb31_cipolla_t::one() {
    return bb31_cipolla_t(bb31_t::one(), bb31_t::zero());
}

bb31_cipolla_t bb31_cipolla_t::mul_ext(bb31_cipolla_t other, bb31_t nonresidue) {
    bb31_t new_real = real * other.real + nonresidue * imag * other.imag;
    bb31_t new_imag = real * other.imag + imag * other.real;
    return bb31_cipolla_t(new_real, new_imag);
}

bb31_cipolla_t bb31_cipolla_t::pow(uint32_t exponent, bb31_t nonresidue) {
    bb31_cipolla_t result = bb31_cipolla_t::one();
    bb31_cipolla_t base = *this;

    while(exponent) {
        if(exponent & 1) {
            result = result.mul_ext(base, nonresidue);
        }
        exponent >>= 1;
        base = base.mul_ext(base, nonresidue);
    }

    return result;
}