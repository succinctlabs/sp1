use p3_field::Field;
use sp1_derive::AlignedBorrow;

use crate::{cpu::Instruction, runtime::Opcode};

const OPCODE_COUNT: usize = core::mem::size_of::<OpcodeSelectorCols<u8>>();

/// Selectors for the opcode.
///
/// This contains selectors for the different opcodes corresponding to variants of the [`Opcode`]
/// enum.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    // Arithmetic field instructions.
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,

    // Arithmetic field extension operations.
    pub is_eadd: T,
    pub is_esub: T,
    pub is_emul: T,
    pub is_ediv: T,

    // Mixed arithmetic operations.
    pub is_efadd: T,
    pub is_efsub: T,
    pub is_fesub: T,
    pub is_efmul: T,
    pub is_efdiv: T,
    pub is_fediv: T,

    // Memory instructions.
    pub is_lw: T,
    pub is_sw: T,
    pub is_le: T,
    pub is_se: T,

    // Branch instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_ebeq: T,
    pub is_ebne: T,

    // Jump instructions.
    pub is_jal: T,
    pub is_jalr: T,

    // System instructions.
    pub is_trap: T,
    pub is_noop: T,
}

impl<F: Field> OpcodeSelectorCols<F> {
    /// Populates the opcode columns with the given instruction.
    ///
    /// The opcode flag should be set to 1 for the relevant opcode and 0 for the rest. We already
    /// assume that the state of the columns is set to zero at the start of the function, so we only
    /// need to set the relevant opcode column to 1.
    pub fn populate(&mut self, instruction: Instruction<F>) {
        match instruction.opcode {
            Opcode::ADD => self.is_add = F::one(),
            Opcode::SUB => self.is_sub = F::one(),
            Opcode::MUL => self.is_mul = F::one(),
            Opcode::DIV => self.is_div = F::one(),
            Opcode::EADD => self.is_eadd = F::one(),
            Opcode::ESUB => self.is_esub = F::one(),
            Opcode::EMUL => self.is_emul = F::one(),
            Opcode::EDIV => self.is_ediv = F::one(),
            Opcode::EFADD => self.is_efadd = F::one(),
            Opcode::EFSUB => self.is_efsub = F::one(),
            Opcode::FESUB => self.is_fesub = F::one(),
            Opcode::EFMUL => self.is_efmul = F::one(),
            Opcode::EFDIV => self.is_efdiv = F::one(),
            Opcode::FEDIV => self.is_fediv = F::one(),
            Opcode::LW => self.is_lw = F::one(),
            Opcode::SW => self.is_sw = F::one(),
            Opcode::LE => self.is_le = F::one(),
            Opcode::SE => self.is_se = F::one(),
            Opcode::BEQ => self.is_beq = F::one(),
            Opcode::BNE => self.is_bne = F::one(),
            Opcode::EBEQ => self.is_ebeq = F::one(),
            Opcode::EBNE => self.is_ebne = F::one(),
            Opcode::JAL => self.is_jal = F::one(),
            Opcode::JALR => self.is_jalr = F::one(),
            Opcode::TRAP => self.is_trap = F::one(),
        }
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;

    type IntoIter = std::array::IntoIter<T, OPCODE_COUNT>;

    fn into_iter(self) -> Self::IntoIter {
        [
            self.is_add,
            self.is_sub,
            self.is_mul,
            self.is_div,
            self.is_eadd,
            self.is_esub,
            self.is_emul,
            self.is_ediv,
            self.is_efadd,
            self.is_efsub,
            self.is_fesub,
            self.is_efmul,
            self.is_efdiv,
            self.is_fediv,
            self.is_lw,
            self.is_sw,
            self.is_le,
            self.is_se,
            self.is_beq,
            self.is_bne,
            self.is_ebeq,
            self.is_ebne,
            self.is_jal,
            self.is_jalr,
            self.is_trap,
            self.is_noop,
        ]
        .into_iter()
    }
}
