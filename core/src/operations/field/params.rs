use crate::air::polynomial::Polynomial;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;
use crate::utils::field::{bigint_into_u16_digits, compute_root_quotient_and_shift};
use core::borrow::{Borrow, BorrowMut};
use p3_field::AbstractField;
use p3_field::Field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Add;
use std::slice::Iter;
use valida_derive::AlignedBorrow;

use num::{BigUint, Zero};

pub const MAX_NB_LIMBS: usize = 32;
pub const LIMB: u32 = 2u32.pow(16);

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned
{
    const NB_BITS_PER_LIMB: usize;
    const NB_LIMBS: usize;
    const NB_WITNESS_LIMBS: usize;
    const MODULUS: [u16; MAX_NB_LIMBS];
    const WITNESS_OFFSET: usize;

    fn modulus() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::MODULUS.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
        }
        modulus
    }

    fn modulus_field_iter<F: Field>() -> impl Iterator<Item = F> {
        Self::MODULUS
            .into_iter()
            .map(|x| F::from_canonical_u16(x))
            .take(Self::NB_LIMBS)
    }

    fn to_limbs<F: Field>(x: &BigUint) -> Limbs<F, 16> {
        let limbs: Vec<F> = bigint_into_u16_digits(x, Self::NB_LIMBS)
            .iter()
            .map(|x| F::from_canonical_u16(*x))
            .collect();
        Limbs(limbs.try_into().unwrap())
    }

    fn to_limbs_as_polynomial<F: Field>(x: &BigUint) -> Polynomial<F> {
        let limbs = Self::to_limbs::<F>(x);
        limbs.into()
    }
}

#[derive(Debug, Clone)]
pub struct Limbs<T, const N: usize>(pub [T; N]);

impl<const N: usize, Var: Into<Expr>, Expr: Clone> From<Limbs<Var, N>> for Polynomial<Expr> {
    fn from(value: Limbs<Var, N>) -> Self {
        Polynomial::from_coefficients_slice(
            &value.0.into_iter().map(|x| x.into()).collect::<Vec<_>>(),
        )
    }
}

impl<'a, Var: Into<Expr> + Clone, Expr: Clone> From<Iter<'a, Var>> for Polynomial<Expr> {
    fn from(value: Iter<'a, Var>) -> Self {
        Polynomial::from_coefficients_slice(&value.map(|x| (*x).clone().into()).collect::<Vec<_>>())
    }
}

impl<const N: usize, T: Debug> From<Polynomial<T>> for Limbs<T, N> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = value.coefficients.try_into().unwrap();
        Self(inner)
    }
}
