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

    /// Whether the second operand is an immediate value.
    pub imm_b: bool,

    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

impl<F: PrimeField32> Instruction<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opcode: Opcode,
        op_a: F,
        op_b: [F; D],
        op_c: [F; D],
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b: Block::from(op_b),
            op_c: Block::from(op_c),
            imm_b,
            imm_c,
        }
    }

    pub(crate) fn is_b_ext(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LE
                | Opcode::SE
                | Opcode::EADD
                | Opcode::ESUB
                | Opcode::EMUL
                | Opcode::EFADD
                | Opcode::EFSUB
                | Opcode::EFMUL
                | Opcode::EDIV
                | Opcode::EFDIV
                | Opcode::EBNE
                | Opcode::EBEQ
        )
    }

    pub(crate) fn is_c_ext(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LE
                | Opcode::SE
                | Opcode::EADD
                | Opcode::EMUL
                | Opcode::ESUB
                | Opcode::FESUB
                | Opcode::EDIV
                | Opcode::FEDIV
                | Opcode::EBNE
                | Opcode::EBEQ
        )
    }

    pub(crate) fn imm_b_base(&self) -> bool {
        self.imm_b && !self.is_b_ext()
    }

    pub(crate) fn imm_c_base(&self) -> bool {
        self.imm_c && !self.is_c_ext()
    }
}
