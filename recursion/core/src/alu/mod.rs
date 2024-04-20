mod air;
mod columns;

use crate::air::Block;
use crate::runtime::Opcode;
use sp1_derive::AlignedBorrow;

#[derive(Debug, Clone)]
pub struct AluEvent<F: Sized> {
    pub a: Block<F>,
    pub b: Block<F>,
    pub c: Block<F>,
    pub opcode: Opcode,
}
