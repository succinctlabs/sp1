use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;
use core::borrow::{Borrow, BorrowMut};
use p3_field::Field;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::size_of;
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

/// A set of columns to compute `a + b` where a, b are field elements.
/// In the future, this will be macro-ed to support different fields.
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct FpAdd<T> {
    /// The result of `a + b`, where a, b are field elements
    pub value: Felt<T>,
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
    pub fn eval<AB: CurtaAirBuilder>(builder: &mut AB, a: Felt<AB::Var>, b: Felt<AB::Var>) {
        // TODO: constraint a, b, value and all the witness columns.
    }
}
