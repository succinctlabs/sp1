use crate::air::polynomial::Polynomial;
use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;
use core::borrow::{Borrow, BorrowMut};
use p3_field::Field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Add;
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
    type Field: Field;

    fn modulus() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::MODULUS.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
        }
        modulus
    }
}

#[derive(Default, Debug, Clone)]
pub struct Felt<T>(pub [T; 16]);

impl<Var: Into<Expr>, Expr: Clone> From<Felt<Var>> for Polynomial<Expr> {
    fn from(value: Felt<Var>) -> Self {
        Polynomial::from_coefficients_slice(
            &value.0.into_iter().map(|x| x.into()).collect::<Vec<_>>(),
        )
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
    pub fn populate<P: Field>(&mut self, a: P, b: P) -> P {
        let result = a + b;
        // self.value = result.into();
        // TODO: fill in carry, witness_low, witness_high
        result
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder>(&self, builder: &mut AB, a: Felt<AB::Var>, b: Felt<AB::Var>) {
        // TODO: constraint a, b, value and all the witness columns.
        let p_a = a.into();
        let p_b = b.into();

        // let p_result = self.result.into();
        // let p_carry = self.carry.into();
        let p_a_plus_b = builder.poly_add(&p_a, &p_b);
        // let p_a_plus_b_minus_result = builder.poly_sub(&p_a_plus_b, &p_result);
        // let p_limbs = builder.constant_poly(&Polynomial::from_iter(util::modulus_field_iter::<
        //     AP::Field,e
        //     P,
        // >()));

        // let p_mul_times_carry = builder.poly_mul(&p_carry, &p_limbs);
        // let p_vanishing = builder.poly_sub(&p_a_plus_b_minus_result, &p_mul_times_carry);

        // let p_witness_low = self.witness_low.into();
        // let p_witness_high = self.witness_high.into();

        // util::eval_field_operation::<AP, P>(parser, &p_vanishing, &p_witness_low, &p_witness_high)
    }
}
