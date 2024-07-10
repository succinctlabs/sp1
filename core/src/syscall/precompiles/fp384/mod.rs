mod fp;

use std::{
    mem::transmute,
    ops::{Add, Mul, Neg, Sub},
};

pub use fp::*;
use num_bigint::BigUint;

use crate::utils::{bytes_to_words_le, words_to_bytes_le_vec};

#[derive(Clone, Copy)]
pub struct Fp([u64; 6]);

impl Fp {
    pub(crate) fn to_words(self) -> [u32; 12] {
        unsafe { transmute(self.0) }
    }

    pub(crate) fn from_words(bytes: &[u32; 12]) -> Self {
        unsafe { Self(transmute(*bytes)) }
    }
}

impl Mul for Fp {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        let rhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&self.to_words()));
        let lhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&other.to_words()));

        let out = (lhs * rhs) % BigUint::from_bytes_le(&words_to_bytes_le_vec(&MODULUS));
        Self::from_words(&bytes_to_words_le::<12>(&out.to_bytes_le()))
    }
}

impl Add for Fp {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let rhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&self.to_words()));
        let lhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&other.to_words()));

        let out = (lhs + rhs) % BigUint::from_bytes_le(&words_to_bytes_le_vec(&MODULUS));
        Self::from_words(&bytes_to_words_le::<12>(&out.to_bytes_le()))
    }
}

impl Neg for Fp {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let val = BigUint::from_bytes_be(&words_to_bytes_le_vec(&self.to_words()));
        let out = BigUint::from_bytes_le(&words_to_bytes_le_vec(&MODULUS)) - val;
        Self::from_words(&bytes_to_words_le::<12>(&out.to_bytes_le()))
    }
}

impl Sub for Fp {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

#[derive(Clone, Copy)]
pub struct Fp2 {
    c0: Fp,
    c1: Fp,
}

impl Fp2 {
    pub(crate) fn to_words(self) -> [u32; 24] {
        let mut bytes = [0; 24];
        bytes[..12].copy_from_slice(&self.c0.to_words());
        bytes[12..].copy_from_slice(&self.c1.to_words());
        bytes
    }

    pub(crate) fn from_words(bytes: &[u32; 24]) -> Self {
        Self {
            c0: Fp::from_words(bytes[..12].try_into().unwrap()),
            c1: Fp::from_words(bytes[12..].try_into().unwrap()),
        }
    }

    fn mul_by_nonresidue(self) -> Self {
        Self {
            c0: self.c0 - self.c1,
            c1: self.c0 + self.c1,
        }
    }
}

impl Mul for Fp2 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Fp2 {
            c0: self.c0 * rhs.c0 - self.c1 * rhs.c1,
            c1: self.c0 * rhs.c1 + self.c1 * rhs.c0,
        }
    }
}

impl Add for Fp2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Neg for Fp2 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Fp6 {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,
}

impl Fp6 {
    pub(crate) fn to_words(&self) -> [u32; 72] {
        let mut bytes = [0; 72];
        bytes[..24].copy_from_slice(&self.c0.to_words());
        bytes[24..48].copy_from_slice(&self.c1.to_words());
        bytes[48..].copy_from_slice(&self.c2.to_words());
        bytes
    }

    pub(crate) fn from_words(bytes: &[u32; 72]) -> Self {
        Self {
            c0: Fp2::from_words(bytes[..24].try_into().unwrap()),
            c1: Fp2::from_words(bytes[24..48].try_into().unwrap()),
            c2: Fp2::from_words(bytes[48..].try_into().unwrap()),
        }
    }

    fn mul_by_nonresidue(&self) -> Fp6 {
        Fp6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }
}

impl Mul for Fp6 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let b10_p_b11 = rhs.c1.c0 + rhs.c1.c1;
        let b10_m_b11 = rhs.c1.c0 - rhs.c1.c1;
        let b20_p_b21 = rhs.c2.c0 + rhs.c2.c1;
        let b20_m_b21 = rhs.c2.c0 - rhs.c2.c1;
        Fp6 {
            c0: Fp2 {
                c0: self.c0.c0 * rhs.c0.c0 - self.c0.c1 * rhs.c0.c1 + self.c1.c0 * b20_m_b21
                    - self.c1.c1 * b20_p_b21
                    + self.c2.c0 * b10_m_b11
                    - self.c2.c1 * b10_p_b11,

                c1: self.c0.c0 * rhs.c0.c1
                    + self.c0.c1 * rhs.c0.c0
                    + self.c1.c0 * b20_p_b21
                    + self.c1.c1 * b20_m_b21
                    + self.c2.c0 * b10_p_b11
                    + self.c2.c1 * b10_m_b11,
            },
            c1: Fp2 {
                c0: self.c0.c0 * rhs.c1.c0 - self.c0.c1 * rhs.c1.c1 + self.c1.c0 * rhs.c0.c0
                    - self.c1.c1 * rhs.c0.c1
                    + self.c2.c0 * b20_m_b21
                    - self.c2.c1 * b20_p_b21,
                c1: self.c0.c0 * rhs.c1.c1
                    + self.c0.c1 * rhs.c1.c0
                    + self.c1.c0 * rhs.c0.c1
                    + self.c1.c1 * rhs.c0.c0
                    + self.c2.c0 * b20_p_b21
                    + self.c2.c1 * b20_m_b21,
            },
            c2: Fp2 {
                c0: self.c0.c0 * rhs.c2.c0 - self.c0.c1 * rhs.c2.c1 + self.c1.c0 * rhs.c1.c0
                    - self.c1.c1 * rhs.c1.c1
                    + self.c2.c0 * rhs.c0.c0
                    - self.c2.c1 * rhs.c0.c1,
                c1: self.c0.c0 * rhs.c2.c1
                    + self.c0.c1 * rhs.c2.c0
                    + self.c1.c0 * rhs.c1.c1
                    + self.c1.c1 * rhs.c1.c0
                    + self.c2.c0 * rhs.c0.c1
                    + self.c2.c1 * rhs.c0.c0,
            },
        }
    }
}

impl Add for Fp6 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Fp6 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl Neg for Fp6 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Fp6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

impl Sub for Fp6 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

pub struct Fp12 {
    c0: Fp6,
    c1: Fp6,
}

impl Fp12 {
    pub(crate) fn to_words(self) -> [u32; 144] {
        let mut bytes = [0; 144];
        bytes[..72].copy_from_slice(&self.c0.to_words());
        bytes[72..].copy_from_slice(&self.c1.to_words());
        bytes
    }

    pub(crate) fn from_words(bytes: &[u32; 144]) -> Self {
        Self {
            c0: Fp6::from_words(bytes[..72].try_into().unwrap()),
            c1: Fp6::from_words(bytes[72..].try_into().unwrap()),
        }
    }
}

impl Add for Fp12 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Mul for Fp12 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let aa = self.c0 * rhs.c0;
        let bb = self.c1 * rhs.c1;
        let o = rhs.c0 + rhs.c1;
        let c1 = self.c1 + self.c0;
        let c1 = c1 * o;
        let c1 = c1 - aa;
        let c1 = c1 - bb;
        let c0 = bb.mul_by_nonresidue();
        let c0 = c0 + aa;

        Fp12 { c0, c1 }
    }
}

const MODULUS: [u32; 12] = [
    0xb9fe_ffff,
    0xffff_aaab,
    0x1eab_fffe,
    0xb153_ffff,
    0x6730_d2a0,
    0xf6b0_f624,
    0x6477_4b84,
    0xf385_12bf,
    0x4b1b_a7b6,
    0x434b_acd7,
    0x1a01_11ea,
    0x397f_e69a,
];
