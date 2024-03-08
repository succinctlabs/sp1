use p3_field::PrimeField32;

use crate::opcode::Opcode;

#[derive(Debug, Clone)]
pub struct Instruction<F> {
    /// Which operation to execute.
    pub opcode: Opcode,

    /// The first operand.
    pub op_a: F,

    /// The second operand.
    pub op_b: F,

    /// The third operand.
    pub op_c: F,

    /// Whether the second operand is an immediate value.
    pub imm_b: bool,

    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

impl<F: PrimeField32> Instruction<F> {
    pub fn new(opcode: Opcode, op_a: u32, op_b: u32, op_c: u32, imm_b: bool, imm_c: bool) -> Self {
        Self {
            opcode,
            op_a: F::from_canonical_u32(op_a),
            op_b: F::from_canonical_u32(op_b),
            op_c: F::from_canonical_u32(op_c),
            imm_b,
            imm_c,
        }
    }
}
