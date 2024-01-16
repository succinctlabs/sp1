use super::params::{FieldParameters, Limbs};
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::polynomial::Polynomial;
use crate::air::CurtaAirBuilder;
use core::borrow::{Borrow, BorrowMut};
use num::BigUint;
use p3_field::{Field, PrimeField, PrimeField32};
use std::fmt::Debug;
use valida_derive::AlignedBorrow;
/// A set of columns to compute `a + b` where a, b are field elements.
/// In the future, this will be macro-ed to support different fields.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct FpAdd<T> {
    /// The result of `a + b`, where a, b are field elements
    pub result: Limbs<T, 32>,
    pub(crate) carry: Limbs<T, 32>,
    pub(crate) witness_low: [T; 32], // TODO: this number will be macro-ed later
    pub(crate) witness_high: [T; 32],
}

impl<F: PrimeField32> FpAdd<F> {
    pub fn populate<P: FieldParameters>(&mut self, a: BigUint, b: BigUint) -> BigUint {
        let p_a: Polynomial<F> = P::to_limbs_field::<F>(&a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F>(&b).into();

        // Compute field addition in the integers.
        let modulus = P::modulus();
        let result = (&a + &b) % &modulus;
        let carry = (&a + &b - &result) / &modulus;
        debug_assert!(result < modulus);
        debug_assert!(carry < modulus);
        debug_assert_eq!(&carry * &modulus, a + b - &result);

        // Make little endian polynomial limbs.
        let p_modulus: Polynomial<F> = P::to_limbs_field::<F>(&modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F>(&carry).into();

        // Compute the vanishing polynomial.
        let p_vanishing: Polynomial<F> = &p_a + &p_b - &p_result - &p_carry * &p_modulus;
        debug_assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();
        self.witness_low = p_witness_low.try_into().unwrap();
        self.witness_high = p_witness_high.try_into().unwrap();

        result
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<F = F>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        // TODO: will have to macro these later
        a: Limbs<AB::Var, 32>,
        b: Limbs<AB::Var, 32>,
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
