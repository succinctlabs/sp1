use std::{
    fmt::Display,
    ops::{Index, IndexMut},
};

use crate::air::SP1AirBuilder;
use arrayref::array_ref;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, Field};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use std::array::IntoIter;
use struct_reflection::{StructReflection, StructReflectionHelper};

/// An array of four u16 limbs to represent a 64-bit value.
///
/// We use the generic type `T` to represent the different representations of a u16 limb, ranging
/// from a `u16` to a `AB::Var` or `AB::Expr`.
#[derive(
    AlignedBorrow,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    StructReflection,
)]
#[repr(C)]
pub struct Word<T>(pub [T; WORD_SIZE]);

impl<T> Word<T> {
    /// Applies `f` to each element of the word.
    pub fn map<F, S>(self, f: F) -> Word<S>
    where
        F: FnMut(T) -> S,
    {
        Word(self.0.map(f))
    }

    /// Extends a variable to a word.
    pub fn extend_var<AB: SP1AirBuilder<Var = T>>(var: T) -> Word<AB::Expr> {
        Word([AB::Expr::zero() + var, AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()])
    }

    /// Extends a half word to a word.
    pub fn extend_half<AB: SP1AirBuilder<Var = T>>(var: &[T; 2]) -> Word<AB::Expr>
    where
        T: Clone,
    {
        Word([
            AB::Expr::zero() + var[0].clone(),
            AB::Expr::zero() + var[1].clone(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ])
    }
}

impl<T: AbstractField + Clone> Word<T> {
    /// Extends a variable to a word.
    pub fn extend_expr<AB: SP1AirBuilder<Expr = T>>(expr: T) -> Word<AB::Expr> {
        Word([AB::Expr::zero() + expr, AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()])
    }

    /// Returns a word with all zero expressions.
    #[must_use]
    pub fn zero<AB: SP1AirBuilder<Expr = T>>() -> Word<T> {
        Word([AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()])
    }

    /// Reduces a word to a single expression.
    pub fn reduce<AB: SP1AirBuilder<Expr = T>>(&self) -> AB::Expr {
        let base = [1, 1 << 16, 1 << 32, 1 << 48].map(AB::Expr::from_wrapped_u64);
        self.0.iter().enumerate().map(|(i, x)| base[i].clone() * x.clone()).sum()
    }

    /// Creates a word from `le_bits`.
    /// Safety: This assumes that the `le_bits` are already checked to be boolean.
    pub fn from_le_bits<AB: SP1AirBuilder<Expr = T>>(
        le_bits: &[impl Into<T> + Clone],
        sign_extend: bool,
    ) -> Word<AB::Expr> {
        assert!(le_bits.len() <= WORD_SIZE * 16);

        let mut limbs = le_bits
            .chunks(16)
            .map(|chunk| {
                chunk.iter().enumerate().fold(AB::Expr::zero(), |a, (i, b)| {
                    a + AB::Expr::from_canonical_u16(1 << i) * (*b).clone().into()
                })
            })
            .collect_vec();

        let sign_bit = (*le_bits.last().unwrap()).clone().into();

        if sign_extend {
            // Sign extend the most significant limb.
            let most_sig_limb = limbs.last_mut().unwrap();
            let most_sig_num_bits = le_bits.len() % 16;
            if most_sig_num_bits > 0 {
                *most_sig_limb = (*most_sig_limb).clone()
                    + (AB::Expr::from_canonical_u32((1 << 16) - (1 << most_sig_num_bits)))
                        * sign_bit.clone();
            }
        }

        let extend_limb = if sign_extend {
            AB::Expr::from_canonical_u16(u16::MAX) * sign_bit.clone()
        } else {
            AB::Expr::zero()
        };

        limbs.resize(WORD_SIZE, extend_limb);

        Word::from_iter(limbs)
    }
}

impl<F: Field> Word<F> {
    /// Converts a word to a u32.
    pub fn to_u32(&self) -> u32 {
        let low = self.0[0].to_string().parse::<u16>().unwrap();
        let high = self.0[1].to_string().parse::<u16>().unwrap();
        ((high as u32) << 16) | (low as u32)
    }

    /// Converts a word to a u64.
    pub fn to_u64(&self) -> u64 {
        let low = self.0[0].to_string().parse::<u16>().unwrap();
        let mid_low = self.0[1].to_string().parse::<u16>().unwrap();
        let mid_high = self.0[2].to_string().parse::<u16>().unwrap();
        let high = self.0[3].to_string().parse::<u16>().unwrap();
        ((high as u64) << 48) | ((mid_high as u64) << 32) | ((mid_low as u64) << 16) | (low as u64)
    }
}

impl<T> Index<usize> for Word<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Word<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: AbstractField> From<u32> for Word<F> {
    fn from(value: u32) -> Self {
        Word([
            F::from_canonical_u16((value & 0xFFFF) as u16),
            F::from_canonical_u16((value >> 16) as u16),
            F::zero(),
            F::zero(),
        ])
    }
}

impl<F: AbstractField> From<u64> for Word<F> {
    fn from(value: u64) -> Self {
        Word([
            F::from_canonical_u16((value & 0xFFFF) as u16),
            F::from_canonical_u16((value >> 16) as u16),
            F::from_canonical_u16((value >> 32) as u16),
            F::from_canonical_u16((value >> 48) as u16),
        ])
    }
}

impl<T> IntoIterator for Word<T> {
    type Item = T;
    type IntoIter = IntoIter<T, WORD_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Clone> FromIterator<T> for Word<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let elements = iter.into_iter().take(WORD_SIZE).collect_vec();

        Word(array_ref![elements, 0, WORD_SIZE].clone())
    }
}

impl<T: Display> Display for Word<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Word(")?;
        for (i, value) in self.0.iter().enumerate() {
            write!(f, "{value}")?;
            if i < self.0.len() - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}
