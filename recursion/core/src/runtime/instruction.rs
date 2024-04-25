use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};

use crate::air::Block;

use super::{Opcode, D};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction<F> {
    /// Which operation to execute.
    pub opcode: Opcode,

    /// The first operand.
    pub op_a: F,

    /// The second operand.
    pub op_b: Block<F>,

    /// The third operand.
    pub op_c: Block<F>,

    // The offset imm operand.
    pub offset_imm: F,

    // The size imm operand.
    pub size_imm: F,

    /// Whether the second operand is an immediate value.
    pub imm_b: bool,

    /// Whether the third operand is an immediate value.
    pub imm_c: bool,

    /// A debug string for the instruction.
    pub debug: String,
}

impl<F: PrimeField32> Instruction<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opcode: Opcode,
        op_a: F,
        op_b: [F; D],
        op_c: [F; D],
        offset_imm: F,
        size_imm: F,
        imm_b: bool,
        imm_c: bool,
        debug: String,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b: Block::from(op_b),
            op_c: Block::from(op_c),
            offset_imm,
            size_imm,
            imm_b,
            imm_c,
            debug,
        }
    }

    pub fn dummy() -> Self {
        Instruction::new(
            Opcode::ADD,
            F::zero(),
            [F::zero(); 4],
            [F::zero(); 4],
            F::zero(),
            F::zero(),
            false,
            false,
            "".to_string(),
        )
    }
}
