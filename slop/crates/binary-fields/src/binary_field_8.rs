// Copyright 2025 The Binius Developers
// Copyright 2025 Irreducible, Inc.
// Modifications copyright 2026 Succinct Labs, Benedikt Bunz, William Wang
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BinaryField8(pub u8);

impl BinaryField8 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    #[inline]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn inverse(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let mut result = Self::ONE;
        let mut square = self;
        for bit in 0..8 {
            if (0xfe_u8 >> bit) & 1 != 0 {
                result *= square;
            }
            square *= square;
        }
        Some(result)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for BinaryField8 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl AddAssign for BinaryField8 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Neg for BinaryField8 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for BinaryField8 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl SubAssign for BinaryField8 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl Mul for BinaryField8 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(reduce(carryless_multiply(self.0, rhs.0)))
    }
}

impl MulAssign for BinaryField8 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[inline]
const fn carryless_multiply(lhs: u8, rhs: u8) -> u16 {
    let mut product = 0;
    let mut bit = 0;
    while bit < 8 {
        if (lhs >> bit) & 1 != 0 {
            product ^= (rhs as u16) << bit;
        }
        bit += 1;
    }
    product
}

#[inline]
const fn reduce(product: u16) -> u8 {
    let high = product >> 8;
    let first_fold = (product & 0xff) ^ high ^ (high << 1) ^ (high << 3) ^ (high << 4);
    let remaining_high = first_fold >> 8;
    ((first_fold & 0xff)
        ^ remaining_high
        ^ (remaining_high << 1)
        ^ (remaining_high << 3)
        ^ (remaining_high << 4)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_matches_aes_vectors() {
        assert_eq!(BinaryField8(0x57) * BinaryField8(0x13), BinaryField8(0xfe));
        assert_eq!(BinaryField8(0x57) * BinaryField8(0x83), BinaryField8(0xc1));
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for value in 1..=u8::MAX {
            let element = BinaryField8(value);
            assert_eq!(element * element.inverse().unwrap(), BinaryField8::ONE);
        }
    }

    #[test]
    fn zero_has_no_inverse() {
        assert_eq!(BinaryField8::ZERO.inverse(), None);
    }

    #[test]
    fn multiplication_is_commutative() {
        for lhs in 0..=u8::MAX {
            for rhs in 0..=u8::MAX {
                assert_eq!(
                    BinaryField8(lhs) * BinaryField8(rhs),
                    BinaryField8(rhs) * BinaryField8(lhs)
                );
            }
        }
    }
}
