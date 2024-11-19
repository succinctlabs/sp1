#include "babybear_septic.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>

using namespace sp1_core_machine_sys;
using namespace sp1_core_machine_sys::septic;

BabyBearSeptic BabyBearSeptic::zero() {
    return BabyBearSeptic(BabyBear::zero());
}

BabyBearSeptic BabyBearSeptic::one() {
    return BabyBearSeptic(BabyBear::one());
}

BabyBearSeptic BabyBearSeptic::two() {
    return BabyBearSeptic(BabyBear::two());
}

BabyBearSeptic BabyBearSeptic::from_canonical_u32(uint32_t n) {
    return BabyBearSeptic(BabyBear::from_canonical_u32(n));
}

BabyBearSeptic& BabyBearSeptic::operator+=(const BabyBear b) {
    return *this;
}

BabyBearSeptic& BabyBearSeptic::operator+=(const BabyBearSeptic b) {
    return *this;
}

BabyBearSeptic& BabyBearSeptic::operator-=(const BabyBear b) {
    return *this;
}

BabyBearSeptic& BabyBearSeptic::operator-=(const BabyBearSeptic b) {
    return *this;
}

BabyBearSeptic& BabyBearSeptic::operator*=(const BabyBear b) {
    return *this;
}

BabyBearSeptic& BabyBearSeptic::operator*=(const BabyBearSeptic b) {
    return *this;
}

BabyBearSeptic BabyBearSeptic::reciprocal() const {
    return BabyBearSeptic(BabyBear::zero());
}

BabyBear BabyBearSeptic::pow_r() const {
    return BabyBear::zero();
}

BabyBearSeptic BabyBearSeptic::sqrt() const {
    return BabyBearSeptic(BabyBear::zero());
}

BabyBearSeptic BabyBearSeptic::pow_r_1() const {
    return BabyBearSeptic(BabyBear::zero());
}

BabyBearSeptic BabyBearSeptic::frobenius() const {
    return BabyBearSeptic(BabyBear::zero());
}

BabyBearSeptic BabyBearSeptic::double_frobenius() const {
    return BabyBearSeptic(BabyBear::zero());
}

BabyBearCipolla BabyBearCipolla::one() const {
    return BabyBearCipolla(BabyBear::one(), BabyBear::zero());
}

BabyBearCipolla BabyBearCipolla::mul_ext(BabyBearCipolla other, BabyBear nonresidue) {
    return BabyBearCipolla(BabyBear::one(), BabyBear::zero());
}

BabyBearCipolla BabyBearCipolla::pow(uint32_t exponent, BabyBear nonresidue) {
    return BabyBearCipolla(BabyBear::one(), BabyBear::zero());
}