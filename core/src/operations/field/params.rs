use crate::air::polynomial::Polynomial;
use crate::utils::field::bigint_into_u8_digits;
use core::borrow::{Borrow, BorrowMut};
use p3_field::AbstractField;
use p3_field::Field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
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
    const MODULUS: [u8; MAX_NB_LIMBS];
    const WITNESS_OFFSET: usize;

    fn modulus() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::MODULUS.iter().enumerate() {
            modulus += BigUint::from(*limb) << (8 * i);
        }
        modulus
    }

    fn modulus_field_iter<F: Field>() -> impl Iterator<Item = F> {
        Self::MODULUS
            .into_iter()
            .map(|x| F::from_canonical_u8(x))
            .take(Self::NB_LIMBS)
    }

    // TODO: macro in the number of limbs.
    fn to_limbs(x: &BigUint) -> Limbs<u8, 32> {
        let bytes = x.to_bytes_le();
        if bytes.len() != 32 {
            panic!("Expected exactly 32 limbs, found {}", bytes.len());
        }
        let mut limbs = [0u8; 32];
        limbs.copy_from_slice(&bytes);
        Limbs(limbs)
    }

    fn to_limbs_field<F: Field>(x: &BigUint) -> Limbs<F, 32> {
        Limbs(
            Self::to_limbs(x)
                .0
                .into_iter()
                .map(|x| F::from_canonical_u8(x))
                .collect::<Vec<F>>()
                .try_into()
                .unwrap(),
        )
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

impl<'a, const N: usize, T: Debug + Clone> From<Iter<'a, T>> for Limbs<T, N> {
    fn from(value: Iter<'a, T>) -> Self {
        let vec: Vec<T> = value.cloned().collect();
        let inner = vec.try_into().unwrap();
        Self(inner)
    }
}
