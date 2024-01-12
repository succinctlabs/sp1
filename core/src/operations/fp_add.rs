use crate::air::polynomial::Polynomial;
use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;
use crate::utils::field::{bigint_into_u16_digits, compute_root_quotient_and_shift};
use core::borrow::{Borrow, BorrowMut};
use p3_field::AbstractField;
use p3_field::Field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Add;
use std::slice::Iter;
use valida_derive::AlignedBorrow;

use num::{BigUint, Zero};

pub const MAX_NB_LIMBS: usize = 32;
pub const LIMB: u32 = 2u32.pow(16);

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned
{
    const NB_BITS_PER_LIMB: usize;
    const NB_LIMBS: usize;
    const NB_WITNESS_LIMBS: usize;
    const MODULUS: [u16; MAX_NB_LIMBS];
    const WITNESS_OFFSET: usize;
    type F: Field;

    fn modulus() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::MODULUS.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
        }
        modulus
    }
}

pub fn modulus_field_iter<F: Field, P: FieldParameters>() -> impl Iterator<Item = F> {
    P::MODULUS
        .into_iter()
        .map(|x| F::from_canonical_u16(x))
        .take(P::NB_LIMBS)
}

#[derive(Default, Debug, Clone)]
pub struct Felt<T>(pub [T; 16]);

pub fn to_u16_le_limbs_polynomial<F: Field, P: FieldParameters>(x: &BigUint) -> Polynomial<F> {
    let num_limbs = bigint_into_u16_digits(x, P::NB_LIMBS)
        .iter()
        .map(|x| F::from_canonical_u16(*x))
        .collect();
    Polynomial::from_coefficients(num_limbs)
}

impl<Var: Into<Expr>, Expr: Clone> From<Felt<Var>> for Polynomial<Expr> {
    fn from(value: Felt<Var>) -> Self {
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

/// A set of columns to compute `a + b` where a, b are field elements.
/// In the future, this will be macro-ed to support different fields.
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct FpAdd<T> {
    /// The result of `a + b`, where a, b are field elements
    pub result: Felt<T>,
    pub(crate) carry: Felt<T>,
    pub(crate) witness_low: [T; 16], // TODO: this number will be macro-ed later
    pub(crate) witness_high: [T; 16],
}

impl<F: Field> FpAdd<F> {
    pub fn populate<P: FieldParameters>(&mut self, a: BigUint, b: BigUint) -> BigUint {
        let p_a = to_u16_le_limbs_polynomial::<F, P>(&a);
        let p_b = to_u16_le_limbs_polynomial::<F, P>(&b);

        // Compute field addition in the integers.
        let modulus = P::modulus();
        let result = (&a + &b) % &modulus;
        let carry = (&a + &b - &result) / &modulus;
        debug_assert!(result < modulus);
        debug_assert!(carry < modulus);
        debug_assert_eq!(&carry * &modulus, a + b - &result);

        // Make little endian polynomial limbs.
        let p_modulus = to_u16_le_limbs_polynomial::<F, P>(&modulus);
        let p_result = to_u16_le_limbs_polynomial::<F, P>(&result);
        let p_carry = to_u16_le_limbs_polynomial::<F, P>(&carry);

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
        a: Felt<AB::Var>,
        b: Felt<AB::Var>,
    ) {
        let p_a = a.into();
        let p_b = b.into();

        let p_result = self.result.clone().into();
        let p_carry = self.carry.clone().into();
        let p_a_plus_b = builder.poly_add(&p_a, &p_b);
        let p_a_plus_b_minus_result = builder.poly_sub(&p_a_plus_b, &p_result);
        let p_limbs = builder.constant_poly(&Polynomial::from_iter(modulus_field_iter::<F, P>()));

        let p_mul_times_carry = builder.poly_mul(&p_carry, &p_limbs);
        let p_vanishing = builder.poly_sub(&p_a_plus_b_minus_result, &p_mul_times_carry);

        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);
    }
}

pub fn eval_field_operation<AB: CurtaAirBuilder, P: FieldParameters>(
    builder: &mut AB,
    p_vanishing: &Polynomial<AB::Expr>,
    p_witness_low: &Polynomial<AB::Expr>,
    p_witness_high: &Polynomial<AB::Expr>,
) {
    // Reconstruct and shift back the witness polynomial
    let limb = AB::F::from_canonical_u32(2u32.pow(16)).into();

    let p_witness_high_mul_limb = builder.poly_scalar_mul(p_witness_high, &limb);
    let p_witness_shifted = builder.poly_add(p_witness_low, &p_witness_high_mul_limb);

    // Shift down the witness polynomial. Shifting is needed to range check that each
    // coefficient w_i of the witness polynomial satisfies |w_i| < 2^20.
    let offset = AB::F::from_canonical_u32(P::WITNESS_OFFSET as u32).into();
    let p_witness = builder.poly_scalar_sub(&p_witness_shifted, &offset);

    // Multiply by (x-2^16) and make the constraint
    let root_monomial = Polynomial::from_coefficients(vec![-limb, AB::F::one().into()]);
    let p_witness_mul_root = builder.poly_mul(&p_witness, &root_monomial);

    let constraints = builder.poly_sub(p_vanishing, &p_witness_mul_root);
    for constr in constraints.coefficients {
        builder.assert_zero(constr);
    }
}
