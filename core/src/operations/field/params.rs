use crate::air::Polynomial;
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_field::PrimeField32;
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

impl<T> IntoIterator for Limbs<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, NUM_LIMBS>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Var: Into<Expr> + Clone, Expr: Clone> From<Limbs<Var>> for Polynomial<Expr> {
    fn from(value: Limbs<Var>) -> Self {
        Polynomial::from_coefficients(&value.0.into_iter().map(|x| x.into()).collect::<Vec<_>>())
    }
}

impl<'a, Var: Into<Expr> + Clone, Expr: Clone> From<Iter<'a, Var>> for Polynomial<Expr> {
    fn from(value: Iter<'a, Var>) -> Self {
        Polynomial::from_coefficients(&value.map(|x| (*x).clone().into()).collect::<Vec<_>>())
    }
}

impl<T: Debug + Default + Clone> From<Polynomial<T>> for Limbs<T> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = value.as_coefficients().try_into().unwrap();
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
        .as_coefficients()
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
    use num::BigUint;

    use crate::utils::ec::{edwards::ed25519::Ed25519BaseField, field::FieldParameters};

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
