use crate::air::Polynomial;
use std::fmt::Debug;
use std::ops::Index;
use std::slice::Iter;
use std::usize;

// pub const NUM_LIMBS: usize = 32;
pub const NB_BITS_PER_LIMB: usize = 8;
// pub const NUM_WITNESS_LIMBS: usize = 2 * NUM_LIMBS - 2;

#[derive(Debug, Clone, Copy)]
pub struct Limbs<T, const N: usize>(pub [T; N]);

impl<T, const N: usize> Default for Limbs<T, N>
where
    T: Default + Copy,
{
    fn default() -> Self {
        Self([T::default(); N])
    }
}

impl<T, const N: usize> Index<usize> for Limbs<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, const N: usize> IntoIterator for Limbs<T, N> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Var: Into<Expr> + Clone, const N: usize, Expr: Clone> From<Limbs<Var, N>>
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

impl<T: Debug + Default + Clone, const N: usize> From<Polynomial<T>> for Limbs<T, N> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = value.as_coefficients().try_into().unwrap();
        Self(inner)
    }
}

impl<'a, T: Debug + Default + Clone, const N: usize> From<Iter<'a, T>> for Limbs<T, N> {
    fn from(value: Iter<'a, T>) -> Self {
        let vec: Vec<T> = value.cloned().collect();
        let inner = vec.try_into().unwrap();
        Self(inner)
    }
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
