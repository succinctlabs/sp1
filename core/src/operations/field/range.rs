use num::BigUint;
use p3_field::PrimeField32;
use sp1_derive::AlignedBorrow;

use crate::{bytes::event::ByteRecord, utils::ec::field::FieldParameters};

use super::params::Limbs;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldRangeCols<T, P: FieldParameters> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) byte_flags: Limbs<T, P::Limbs>,
}

impl<F: PrimeField32, P: FieldParameters> FieldRangeCols<F, P> {
    fn populate(&mut self, record: &mut impl ByteRecord, shard: u32, value: &BigUint) {}
}
