use crate::air::Block;
use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AluCols<T> {
    pub ext_a: Block<T>,

    pub ext_b: Block<T>,

    // c = a + b;
    pub add_scratch: Block<T>,

    // c = a - b;
    pub sub_scratch: Block<T>,

    // c = a * b;
    pub mul_scratch: Block<T>,
}
