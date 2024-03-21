use super::utils::biguint_from_limbs;
use crate::operations::field::params::{Limbs, NumLimbs, NB_BITS_PER_LIMB};
use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use num::BigUint;
use p3_field::Field;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

pub const MAX_NB_LIMBS: usize = 32;

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned + NumLimbs
{
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const WITNESS_OFFSET: usize = 1usize << 13;
    const MODULUS: &'static [u8];

    fn modulus() -> BigUint {
        biguint_from_limbs(Self::MODULUS)
    }

    fn nb_bits() -> usize {
        Self::NB_BITS_PER_LIMB * Self::NB_LIMBS
    }

    fn modulus_field_iter<F: Field>() -> impl Iterator<Item = F> {
        Self::MODULUS
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .take(Self::NB_LIMBS)
    }

    fn to_limbs(x: &BigUint) -> Vec<u8> {
        let mut bytes = x.to_bytes_le();
        bytes.resize(Self::NB_LIMBS, 0u8);
        bytes
    }

    fn to_limbs_field<F: Field>(x: &BigUint) -> Vec<F> {
        Self::to_limbs(x)
            .into_iter()
            .map(|x| F::from_canonical_u8(x))
            .collect()
    }
}

/// Convert a vec of u8 limbs to a Limbs of NUM_LIMBS.
pub fn limbs_from_vec<F: Field, N: ArrayLength>(limbs: Vec<F>) -> Limbs<F, N> {
    debug_assert_eq!(limbs.len(), N::USIZE);
    let mut result = GenericArray::<F, N>::generate(|_i| F::zero());
    for (i, limb) in limbs.into_iter().enumerate() {
        result[i] = limb;
    }
    Limbs(result)
}
