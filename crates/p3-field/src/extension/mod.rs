use core::{debug_assert, debug_assert_eq, iter};

use crate::field::Field;
use crate::{naive_poly_mul, ExtensionField};

mod binomial_extension;
mod complex;

use alloc::vec;
use alloc::vec::Vec;

pub use binomial_extension::*;
pub use complex::*;

/// Binomial extension field trait.
/// A extension field with a irreducible polynomial X^d-W
/// such that the extension is `F[X]/(X^d-W)`.
pub trait BinomiallyExtendable<const D: usize>: Field {
    fn w() -> Self;

    // DTH_ROOT = W^((n - 1)/D).
    // n is the order of base field.
    // Only works when exists k such that n = kD + 1.
    fn dth_root() -> Self;

    fn ext_generator() -> [Self; D];
}

pub trait HasFrobenius<F: Field>: ExtensionField<F> {
    fn frobenius(&self) -> Self;
    fn repeated_frobenius(&self, count: usize) -> Self;
    fn frobenius_inv(&self) -> Self;

    fn minimal_poly(mut self) -> Vec<F> {
        let mut m = vec![Self::one()];
        for _ in 0..Self::D {
            m = naive_poly_mul(&m, &[-self, Self::one()]);
            self = self.frobenius();
        }
        let mut m_iter = m
            .into_iter()
            .map(|c| c.as_base().expect("Extension is not algebraic?"));
        let m: Vec<F> = m_iter.by_ref().take(Self::D + 1).collect();
        debug_assert_eq!(m.len(), Self::D + 1);
        debug_assert_eq!(m.last(), Some(&F::one()));
        debug_assert!(m_iter.all(|c| c.is_zero()));
        m
    }

    fn galois_group(self) -> Vec<Self> {
        iter::successors(Some(self), |x| Some(x.frobenius()))
            .take(Self::D)
            .collect()
    }
}

/// Optional trait for implementing Two Adic Binomial Extension Field.
pub trait HasTwoAdicBionmialExtension<const D: usize>: BinomiallyExtendable<D> {
    const EXT_TWO_ADICITY: usize;

    fn ext_two_adic_generator(bits: usize) -> [Self; D];
}
