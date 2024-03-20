use crate::air::Block;
use p3_field::PrimeField;
use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AluCols<T> {
    pub ext_a: Block<T>,

    pub ext_b: Block<T>,

    // c = a + b;
    pub add_scratch: T,

    // c = a - b;
    pub sub_scratch: T,

    // c = a * b;
    pub mul_scratch: T,

    // ext(c) = ext(a) + ext(b);
    pub add_ext_scratch: Block<T>,

    // ext(c) = ext(a) - ext(b);
    pub sub_ext_scratch: Block<T>,

    // ext(c) = ext(a) * ext(b);
    pub mul_ext_scratch: Block<T>,
}
