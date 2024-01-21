use crate::air::polynomial::Polynomial;
use num::{BigUint, One};
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_field::PrimeField32;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::ops::Index;
use std::slice::Iter;

pub const NUM_LIMBS: usize = 32;
pub const NB_BITS_PER_LIMB: usize = 8;
pub const NUM_WITNESS_LIMBS: usize = 2 * NUM_LIMBS - 2;

#[derive(Default, Debug, Clone, Copy)]
pub struct Limbs<T>(pub [T; NUM_LIMBS]);

impl<T> Index<usize> for Limbs<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct AffinePoint<T> {
    pub x: Limbs<T>,
    pub y: Limbs<T>,
}

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned
{
    const NB_BITS_PER_LIMB: usize;
    const NB_LIMBS: usize;
    const NB_WITNESS_LIMBS: usize;
    const MODULUS: [u8; NUM_LIMBS];
    const WITNESS_OFFSET: usize;

    fn modulus() -> BigUint;

    fn modulus_field_iter<F: Field>() -> impl Iterator<Item = F> {
        Self::MODULUS
            .into_iter()
            .map(|x| F::from_canonical_u8(x))
            .take(Self::NB_LIMBS)
    }

    fn to_limbs(x: &BigUint) -> Limbs<u8> {
        let mut bytes = x.to_bytes_le();
        bytes.resize(NUM_LIMBS, 0u8);
        let mut limbs = [0u8; NUM_LIMBS];
        limbs.copy_from_slice(&bytes);
        Limbs(limbs)
    }

    fn to_limbs_field<F: Field>(x: &BigUint) -> Limbs<F> {
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Ed25519BaseField;

impl FieldParameters for Ed25519BaseField {
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize = NUM_LIMBS;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const MODULUS: [u8; NUM_LIMBS] = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];
    const WITNESS_OFFSET: usize = 1usize << 13;

    fn modulus() -> BigUint {
        (BigUint::one() << 255) - BigUint::from(19u32)
    }
}

impl<Var: Into<Expr> + Clone, Expr: Clone> From<Limbs<Var>> for Polynomial<Expr> {
    fn from(value: Limbs<Var>) -> Self {
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

impl<T: Debug + Default + Clone> From<Polynomial<T>> for Limbs<T> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = value.coefficients.try_into().unwrap();
        Self(inner)
    }
}

impl<'a, T: Debug + Default + Clone> From<Iter<'a, T>> for Limbs<T> {
    fn from(value: Iter<'a, T>) -> Self {
        let vec: Vec<T> = value.cloned().collect();
        let inner = vec.try_into().unwrap();
        Self(inner)
    }
}

// TODO: we probably won't need this in the future when we do things properly.
pub fn convert_polynomial<F: Field>(value: Polynomial<BabyBear>) -> Limbs<F> {
    let inner_u8 = value
        .coefficients
        .iter()
        .map(|x| x.as_canonical_u32() as u8)
        .map(|x| F::from_canonical_u8(x))
        .collect::<Vec<_>>();
    let inner = inner_u8.try_into().unwrap();
    Limbs(inner)
}

// TODO: we probably won't need this in the future when we do things properly.
pub fn convert_vec<F: Field>(value: Vec<BabyBear>) -> Vec<F> {
    value
        .iter()
        .map(|x| x.as_canonical_u32() as u8)
        .map(|x| F::from_canonical_u8(x))
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulus() {
        // Convert the MODULUS array to BigUint
        let array_modulus = BigUint::from_bytes_le(&Ed25519BaseField::MODULUS);

        // Get the modulus from the function
        let func_modulus = Ed25519BaseField::modulus();

        // println!("array_modulus: {:?}", func_modulus.to_bytes_le());

        // Assert equality
        assert_eq!(
            array_modulus, func_modulus,
            "MODULUS array does not match the modulus() function output."
        );
    }
}
