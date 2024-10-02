use crate::air::Block;
use sp1_derive::AlignedBorrow;
use std::{iter::once, vec::IntoIter};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct InstructionCols<T> {
    pub opcode: T,
    pub op_a: T,
    pub op_b: Block<T>,
    pub op_c: Block<T>,
    pub imm_b: T,
    pub imm_c: T,
    pub offset_imm: T,
    pub size_imm: T,
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(once(self.op_a))
            .chain(self.op_b)
            .chain(self.op_c)
            .chain(once(self.imm_b))
            .chain(once(self.imm_c))
            .chain(once(self.offset_imm))
            .chain(once(self.size_imm))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
