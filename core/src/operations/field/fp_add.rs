use super::params::{FieldParameters, Limbs};
use super::util_air::eval_field_operation;
use crate::air::polynomial::Polynomial;
use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;
use crate::utils::field::{bigint_into_u16_digits, compute_root_quotient_and_shift};
use core::borrow::{Borrow, BorrowMut};
use num::{BigUint, Zero};
use p3_field::AbstractField;
use p3_field::Field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Add;
use std::slice::Iter;
use valida_derive::AlignedBorrow;

/// A set of columns to compute `a + b` where a, b are field elements.
/// In the future, this will be macro-ed to support different fields.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct FpAdd<T> {
    /// The result of `a + b`, where a, b are field elements
    pub result: Limbs<T, 16>,
    pub(crate) carry: Limbs<T, 16>,
    pub(crate) witness_low: [T; 16], // TODO: this number will be macro-ed later
    pub(crate) witness_high: [T; 16],
}

impl<F: Field> FpAdd<F> {
    pub fn populate<P: FieldParameters>(&mut self, a: BigUint, b: BigUint) -> BigUint {
        let p_a = P::to_limbs_as_polynomial::<F>(&a);
        let p_b = P::to_limbs_as_polynomial::<F>(&b);

        // Compute field addition in the integers.
        let modulus = P::modulus();
        let result = (&a + &b) % &modulus;
        let carry = (&a + &b - &result) / &modulus;
        debug_assert!(result < modulus);
        debug_assert!(carry < modulus);
        debug_assert_eq!(&carry * &modulus, a + b - &result);

        // Make little endian polynomial limbs.
        let p_modulus = P::to_limbs_as_polynomial::<F>(&modulus);
        let p_result = P::to_limbs_as_polynomial::<F>(&result);
        let p_carry = P::to_limbs_as_polynomial::<F>(&carry);

        // Compute the vanishing polynomial.
        let p_vanishing = &p_a + &p_b - &p_result - &p_carry * &p_modulus;
        debug_assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

        // Compute the witness.
        // let p_witness = compute_root_quotient_and_shift(&p_vanishing, P::WITNESS_OFFSET);
        // let (p_witness_low, p_witness_high) = split_u32_limbs_to_u16_limbs(&p_witness);

        result
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<F = F>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        a: Limbs<AB::Var, 16>,
        b: Limbs<AB::Var, 16>,
    ) {
        let p_a = a.into();
        let p_b = b.into();

        let p_result = self.result.clone().into();
        let p_carry = self.carry.clone().into();
        let p_a_plus_b = builder.poly_add(&p_a, &p_b);
        let p_a_plus_b_minus_result = builder.poly_sub(&p_a_plus_b, &p_result);
        let p_limbs = builder.constant_poly(&Polynomial::from_iter(P::modulus_field_iter::<F>()));

        let p_mul_times_carry = builder.poly_mul(&p_carry, &p_limbs);
        let p_vanishing = builder.poly_sub(&p_a_plus_b_minus_result, &p_mul_times_carry);

        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);
    }
}
