use crate::air::polynomial::Polynomial;
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_field::PrimeField32;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::slice::Iter;

use num::{BigUint, One, Zero};

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

    fn to_limbs(x: &BigUint) -> Limbs<u8> {
        let bytes = x.to_bytes_le();
        if bytes.len() != 32 {
            panic!("Expected exactly 32 limbs, found {}", bytes.len());
        }
        let mut limbs = [0u8; 32];
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
    const NB_BITS_PER_LIMB: usize = 16;
    const NB_LIMBS: usize = 16;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const MODULUS: [u8; MAX_NB_LIMBS] = [0u8; MAX_NB_LIMBS];
    // 65517, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
    // 65535, 65535, 32767, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // ];
    const WITNESS_OFFSET: usize = 1usize << 20;

    fn modulus() -> BigUint {
        (BigUint::one() << 255) - BigUint::from(19u32)
    }
}

pub const NUM_LIMBS: usize = 32;
#[derive(Default, Debug, Clone)]
pub struct Limbs<T>(pub [T; NUM_LIMBS]);

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
pub fn convert_vec<F: Field>(value: Vec<BabyBear>) -> Limbs<F> {
    let inner_u8 = value
        .iter()
        .map(|x| x.as_canonical_u32() as u8)
        .map(|x| F::from_canonical_u8(x))
        .collect::<Vec<_>>();
    let inner = inner_u8.try_into().unwrap();
    Limbs(inner)
}
