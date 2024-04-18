use std::fmt::Debug;
use std::ops::Div;

use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use num::BigUint;
use p3_field::Field;
use serde::{de::DeserializeOwned, Serialize};
use typenum::Unsigned;
use typenum::{U2, U4};

use super::utils::biguint_from_limbs;
use crate::operations::field::params::{Limbs, NB_BITS_PER_LIMB};

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned + NumLimbs
{
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize = Self::Limbs::USIZE;
    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;
    const WITNESS_OFFSET: usize = 1usize << 16;
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

    /// Convert a BigUint to a Vec of u8 limbs (with len NB_LIMBS).
    fn to_limbs(x: &BigUint) -> Vec<u8> {
        let mut bytes = x.to_bytes_le();
        bytes.resize(Self::NB_LIMBS, 0u8);
        bytes
    }

    /// Convert a BigUint to a Vec of F limbs (with len NB_LIMBS).
    fn to_limbs_field_vec<E: From<F>, F: Field>(x: &BigUint) -> Vec<E> {
        Self::to_limbs(x)
            .into_iter()
            .map(|x| F::from_canonical_u8(x).into())
            .collect::<Vec<_>>()
    }

    /// Convert a BigUint to Limbs<F, Self::Limbs>.
    fn to_limbs_field<E: From<F>, F: Field>(x: &BigUint) -> Limbs<E, Self::Limbs> {
        limbs_from_vec(Self::to_limbs_field_vec(x))
    }
}

/// Convert a vec of u8 limbs to a Limbs of N length.
pub fn limbs_from_vec<E: From<F>, N: ArrayLength, F: Field>(limbs: Vec<E>) -> Limbs<E, N> {
    debug_assert_eq!(limbs.len(), N::USIZE);
    let mut result = GenericArray::<E, N>::generate(|_i| F::zero().into());
    for (i, limb) in limbs.into_iter().enumerate() {
        result[i] = limb;
    }
    Limbs(result)
}

/// Trait that holds the typenum values for # of limbs and # of witness limbs.
pub trait NumLimbs: Clone + Debug {
    type Limbs: ArrayLength + Debug;
    type Witness: ArrayLength + Debug;
}

/// Trait that holds number of words needed to represent a field element and a curve point.
pub trait NumWords: Clone + Debug {
    /// The number of words needed to represent a field element.
    type WordsFieldElement: ArrayLength + Debug;
    /// The number of words needed to represent a curve point (two field elements).
    type WordsCurvePoint: ArrayLength + Debug;
}

/// Implement NumWords for NumLimbs where # Limbs is divisible by 4.
///
/// Using typenum we can do N/4 and N/2 in type-level arithmetic. Having it as a separate trait
/// avoids needing the Div where clauses everywhere.
impl<N: NumLimbs> NumWords for N
where
    N::Limbs: Div<U4>,
    N::Limbs: Div<U2>,
    <N::Limbs as Div<U4>>::Output: ArrayLength + Debug,
    <N::Limbs as Div<U2>>::Output: ArrayLength + Debug,
{
    /// Each word has 4 limbs so we divide by 4.
    type WordsFieldElement = <N::Limbs as Div<U4>>::Output;
    /// Curve point has 2 field elements so we divide by 2.
    type WordsCurvePoint = <N::Limbs as Div<U2>>::Output;
}
