mod fp;
mod fp12;

use std::{
    mem::transmute,
    ops::{Add, Mul, Neg, Sub},
};

pub use fp::*;
pub use fp12::*;

use num_bigint::BigUint;

use crate::{
    operations::field::params::FieldParameters,
    utils::{bytes_to_words_le, words_to_bytes_le_vec},
};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Fp<F: FieldParameters> {
    data: [u64; 6],
    _field: std::marker::PhantomData<F>,
}

impl<F: FieldParameters> Fp<F> {
    pub(crate) fn to_words(self) -> [u32; 12] {
        unsafe { transmute(self.data) }
    }

    pub(crate) fn from_words(bytes: &[u32; 12]) -> Self {
        unsafe {
            Self {
                data: transmute(*bytes),
                _field: std::marker::PhantomData,
            }
        }
    }
}

impl<F: FieldParameters> Mul for Fp<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        let rhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&self.to_words()));
        let lhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&other.to_words()));

        let out = (lhs * rhs) % BigUint::from_bytes_le(F::MODULUS);
        Self::from_words(&bytes_to_words_le::<12>(&out.to_bytes_le()))
    }
}

impl<F: FieldParameters> Add for Fp<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let rhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&self.to_words()));
        let lhs = BigUint::from_bytes_be(&words_to_bytes_le_vec(&other.to_words()));

        let out = (lhs + rhs) % BigUint::from_bytes_le(F::MODULUS);
        Self::from_words(&bytes_to_words_le::<12>(&out.to_bytes_le()))
    }
}

impl<F: FieldParameters> Neg for Fp<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let val = BigUint::from_bytes_be(&words_to_bytes_le_vec(&self.to_words()));
        let out = BigUint::from_bytes_le(F::MODULUS) - val;
        Self::from_words(&bytes_to_words_le::<12>(&out.to_bytes_le()))
    }
}

impl<F: FieldParameters> Sub for Fp<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Fp2<F: FieldParameters> {
    c0: Fp<F>,
    c1: Fp<F>,
}

impl<F: FieldParameters> Fp2<F> {
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

impl<F: FieldParameters> Mul for Fp2<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Fp2 {
            c0: self.c0 * rhs.c0 - self.c1 * rhs.c1,
            c1: self.c0 * rhs.c1 + self.c1 * rhs.c0,
        }
    }
}

impl<F: FieldParameters> Add for Fp2<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl<F: FieldParameters> Neg for Fp2<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Fp6<F: FieldParameters> {
    c0: Fp2<F>,
    c1: Fp2<F>,
    c2: Fp2<F>,
}

impl<F: FieldParameters> Fp6<F> {
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

    fn mul_by_nonresidue(&self) -> Fp6<F> {
        Fp6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }
}

impl<F: FieldParameters> Mul for Fp6<F> {
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

impl<F: FieldParameters> Add for Fp6<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Fp6 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl<F: FieldParameters> Neg for Fp6<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Fp6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

impl<F: FieldParameters> Sub for Fp6<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Fp12<F: FieldParameters> {
    c0: Fp6<F>,
    c1: Fp6<F>,
}

impl<F: FieldParameters> Fp12<F> {
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

impl<F: FieldParameters> Add for Fp12<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl<F: FieldParameters> Mul for Fp12<F> {
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
