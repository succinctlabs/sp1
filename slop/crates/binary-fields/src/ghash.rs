// Copyright 2025 The Binius Developers
// Copyright 2025 Irreducible, Inc.
// Modifications copyright 2026 Succinct Labs, Benedikt Bunz, William Wang
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! GF(2^128) with the GHASH polynomial x^128 + x^7 + x^2 + x + 1.

use core::ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C, align(16))]
pub struct GHash {
    pub lo: u64,
    pub hi: u64,
}

impl GHash {
    pub const ZERO: Self = Self { lo: 0, hi: 0 };
    pub const ONE: Self = Self { lo: 1, hi: 0 };
    pub const GENERATOR: Self = Self { lo: 2, hi: 0 };

    #[inline]
    pub const fn new(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[inline]
    pub fn multiply_unreduced(self, rhs: Self) -> GHashUnreduced {
        multiply_unreduced(self, rhs)
    }

    pub fn inverse(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let mut result = Self::ONE;
        let mut square = self * self;
        for _ in 1..128 {
            result *= square;
            square *= square;
        }
        Some(result)
    }

    #[inline]
    pub const fn multiply_by_generator(self) -> Self {
        let carry = self.hi >> 63;
        let reduction_mask = 0_u64.wrapping_sub(carry);
        Self { lo: (self.lo << 1) ^ (0x87 & reduction_mask), hi: (self.hi << 1) | (self.lo >> 63) }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for GHash {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self { lo: self.lo ^ rhs.lo, hi: self.hi ^ rhs.hi }
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl AddAssign for GHash {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.lo ^= rhs.lo;
        self.hi ^= rhs.hi;
    }
}

impl Neg for GHash {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for GHash {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl SubAssign for GHash {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl Mul for GHash {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        multiply_unreduced(self, rhs).reduce()
    }
}

impl MulAssign for GHash {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GHashUnreduced {
    limbs: [u64; 4],
}

impl GHashUnreduced {
    pub const ZERO: Self = Self { limbs: [0; 4] };

    #[inline]
    pub fn reduce(self) -> GHash {
        reduce(self.limbs)
    }
}

impl BitXor for GHashUnreduced {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self { limbs: core::array::from_fn(|index| self.limbs[index] ^ rhs.limbs[index]) }
    }
}

impl BitXorAssign for GHashUnreduced {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        for (limb, rhs_limb) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb ^= rhs_limb;
        }
    }
}

#[inline]
fn carryless_multiply(lhs: u64, rhs: u64) -> (u64, u64) {
    let mut low = 0;
    let mut high = 0;
    for bit in 0..64 {
        if (lhs >> bit) & 1 != 0 {
            low ^= rhs << bit;
            if bit != 0 {
                high ^= rhs >> (64 - bit);
            }
        }
    }
    (low, high)
}

#[inline]
fn multiply_unreduced(lhs: GHash, rhs: GHash) -> GHashUnreduced {
    let (low_low, low_high) = carryless_multiply(lhs.lo, rhs.lo);
    let (lhs_cross_low, lhs_cross_high) = carryless_multiply(lhs.lo, rhs.hi);
    let (rhs_cross_low, rhs_cross_high) = carryless_multiply(lhs.hi, rhs.lo);
    let (high_low, high_high) = carryless_multiply(lhs.hi, rhs.hi);

    GHashUnreduced {
        limbs: [
            low_low,
            low_high ^ lhs_cross_low ^ rhs_cross_low,
            high_low ^ lhs_cross_high ^ rhs_cross_high,
            high_high,
        ],
    }
}

#[inline]
fn reduce([r0, r1, r2, r3]: [u64; 4]) -> GHash {
    let shifted_1 = (r2 << 1, (r3 << 1) | (r2 >> 63));
    let shifted_2 = (r2 << 2, (r3 << 2) | (r2 >> 62));
    let shifted_7 = (r2 << 7, (r3 << 7) | (r2 >> 57));
    let folded_low = r2 ^ shifted_1.0 ^ shifted_2.0 ^ shifted_7.0;
    let folded_high = r3 ^ shifted_1.1 ^ shifted_2.1 ^ shifted_7.1;
    let overflow = (r3 >> 63) ^ (r3 >> 62) ^ (r3 >> 57);
    let correction = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);

    GHash { lo: r0 ^ folded_low ^ correction, hi: r1 ^ folded_high }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defining_polynomial_identity_holds() {
        let x_127 = GHash::new(0, 1_u64 << 63);
        assert_eq!(GHash::GENERATOR * x_127, GHash::new(0x87, 0));
    }

    #[test]
    fn generator_fast_path_matches_multiplication() {
        let values = [GHash::ZERO, GHash::ONE, GHash::new(u64::MAX, u64::MAX)];
        for value in values {
            assert_eq!(value.multiply_by_generator(), value * GHash::GENERATOR);
        }
    }

    #[test]
    fn deferred_reduction_matches_direct_multiplication() {
        let lhs = GHash::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
        let rhs = GHash::new(0xdead_beef_cafe_babe, 0x1020_3040_5060_7080);
        assert_eq!(lhs.multiply_unreduced(rhs).reduce(), lhs * rhs);
    }

    #[test]
    fn nonzero_element_has_an_inverse() {
        let element = GHash::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
        assert_eq!(element * element.inverse().unwrap(), GHash::ONE);
    }

    #[test]
    fn zero_has_no_inverse() {
        assert_eq!(GHash::ZERO.inverse(), None);
    }
}
