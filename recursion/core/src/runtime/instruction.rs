use p3_field::PrimeField32;

use crate::air::Block;

use super::{Opcode, D};

#[derive(Debug, Clone)]
pub struct Instruction<F> {
    /// Which operation to execute.
    pub opcode: Opcode,

    /// The first operand.
    pub op_a: F,

    /// The second operand.
    pub op_b: Block<F>,

    /// The third operand.
    pub op_c: Block<F>,

    /// Whether the second operand is an immediate field value.
    pub imm_b: bool,

    /// Whether the second operand is an immediate extension value.
    pub imm_ext_b: bool,

    /// Whether the third operand is an immediate value.
    pub imm_c: bool,

    /// Whether the third operand is an immediate extension value.
    pub imm_ext_c: bool,
}

impl<F: PrimeField32> Instruction<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opcode: Opcode,
        op_a: F,
        op_b: [F; D],
        op_c: [F; D],
        imm_b: bool,
        imm_ext_b: bool,
        imm_c: bool,
        imm_ext_c: bool,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b: Block::from(op_b),
            op_c: Block::from(op_c),
            imm_b,
            imm_ext_b,
            imm_c,
            imm_ext_c,
        }
    }
}
