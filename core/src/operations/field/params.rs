use std::fmt::Debug;
use std::ops::{Div, Index, IndexMut};
use std::slice::Iter;

use serde::de::DeserializeOwned;
use serde::Serialize;

use typenum::Unsigned;
use typenum::{U2, U4};

use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use num::BigUint;

use p3_field::Field;

use crate::air::Polynomial;
use crate::utils::ec::utils::biguint_from_limbs;

pub const NB_BITS_PER_LIMB: usize = 8;

/// An array representing N limbs of T.
///
/// GenericArray allows us to constrain the correct array lengths so we can have # of limbs and # of
/// witness limbs associated in NumLimbs / FieldParameters.
/// See: https://github.com/RustCrypto/traits/issues/1481
#[derive(Debug, Clone)]
pub struct Limbs<T, N: ArrayLength>(pub GenericArray<T, N>);

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned + NumLimbs
{
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;
    const NB_LIMBS: usize = Self::Limbs::USIZE;
    const NB_WITNESS_LIMBS: usize = Self::Witness::USIZE;
    const WITNESS_OFFSET: usize;

    /// The bytes of the modulus in little-endian order.
    const MODULUS: &'static [u8];
    /// The bytes of the modulus inverse in little-endian order.
    const R_INV: &'static [u8] = &[1];

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

/// Convert a vec of F limbs to a Limbs of N length.
pub fn limbs_from_vec<E: From<F>, N: ArrayLength, F: Field>(limbs: Vec<F>) -> Limbs<E, N> {
    debug_assert_eq!(limbs.len(), N::USIZE);
    let mut result = GenericArray::<E, N>::generate(|_i| F::zero().into());
    for (i, limb) in limbs.into_iter().enumerate() {
        result[i] = limb.into();
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

impl<T: Copy, N: ArrayLength> Copy for Limbs<T, N> where N::ArrayType<T>: Copy {}

impl<T, N: ArrayLength> Default for Limbs<T, N>
where
    T: Default + Copy,
{
    fn default() -> Self {
        Self(GenericArray::default())
    }
}

impl<T, N: ArrayLength> Index<usize> for Limbs<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, N: ArrayLength> IndexMut<usize> for Limbs<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T, N: ArrayLength> IntoIterator for Limbs<T, N> {
    type Item = T;
    type IntoIter = <GenericArray<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Var: Into<Expr> + Clone, N: ArrayLength, Expr: Clone> From<Limbs<Var, N>>
    for Polynomial<Expr>
{
    fn from(value: Limbs<Var, N>) -> Self {
        Polynomial::from_coefficients(&value.0.into_iter().map(|x| x.into()).collect::<Vec<_>>())
    }
}

impl<'a, Var: Into<Expr> + Clone, Expr: Clone> From<Iter<'a, Var>> for Polynomial<Expr> {
    fn from(value: Iter<'a, Var>) -> Self {
        Polynomial::from_coefficients(&value.map(|x| (*x).clone().into()).collect::<Vec<_>>())
    }
}

impl<T: Debug + Default + Clone, N: ArrayLength> From<Polynomial<T>> for Limbs<T, N> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = value.as_coefficients().try_into().unwrap();
        Self(inner)
    }
}

impl<'a, T: Debug + Default + Clone, N: ArrayLength> From<Iter<'a, T>> for Limbs<T, N> {
    fn from(value: Iter<'a, T>) -> Self {
        let vec: Vec<T> = value.cloned().collect();
        let inner = vec.try_into().unwrap();
        Self(inner)
    }
}

#[cfg(test)]
mod tests {
    use crate::operations::field::params::FieldParameters;
    use num::BigUint;

    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;

    #[test]
    fn test_modulus() {
        // Convert the MODULUS array to BigUint
        let array_modulus = BigUint::from_bytes_le(Ed25519BaseField::MODULUS);

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
