use super::utils::biguint_from_limbs;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::NB_BITS_PER_LIMB;
use crate::operations::field::params::NUM_LIMBS;
use num::BigUint;
use p3_field::Field;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{Debug, Display, Formatter, Result};

pub const MAX_NB_LIMBS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum FieldType {
    Secp256k1,
    Bn254,
    Ed25519,
}

impl Display for FieldType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            FieldType::Secp256k1 => write!(f, "Secp256k1"),
            FieldType::Bn254 => write!(f, "Bn254"),
            FieldType::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned
{
    const FIELD_TYPE: FieldType;
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize = NUM_LIMBS;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const WITNESS_OFFSET: usize = 1usize << 13;
    const MODULUS: [u8; NUM_LIMBS];

    fn modulus() -> BigUint {
        biguint_from_limbs(&Self::MODULUS)
    }

    fn nb_bits() -> usize {
        Self::NB_BITS_PER_LIMB * Self::NB_LIMBS
    }

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
