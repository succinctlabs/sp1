use p3_field::PrimeField32;
use sp1_derive::AlignedBorrow;

use crate::{
    cpu::Instruction,
    runtime::{instruction_is_heap_expand, Opcode},
};

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
    pub is_ext: T,

    // Memory instructions.
    pub is_load: T,
    pub is_store: T,

    // Branch instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_bneinc: T,

    // Jump instructions.
    pub is_jal: T,
    pub is_jalr: T,

    // System instructions.
    pub is_trap: T,
    pub is_noop: T,
    pub is_halt: T,

    pub is_poseidon: T,
    pub is_fri_fold: T,
    pub is_commit: T,
    pub is_ext_to_felt: T,
    pub is_exp_reverse_bits_len: T,
    pub is_heap_expand: T,
}

impl<F: PrimeField32> OpcodeSelectorCols<F> {
    /// Populates the opcode columns with the given instruction.
    ///
    /// The opcode flag should be set to 1 for the relevant opcode and 0 for the rest. We already
    /// assume that the state of the columns is set to zero at the start of the function, so we only
    /// need to set the relevant opcode column to 1.
    pub fn populate(&mut self, instruction: &Instruction<F>) {
        match instruction.opcode {
            Opcode::ADD | Opcode::EADD => self.is_add = F::one(),
            Opcode::SUB | Opcode::ESUB => self.is_sub = F::one(),
            Opcode::MUL | Opcode::EMUL => self.is_mul = F::one(),
            Opcode::DIV | Opcode::EDIV => self.is_div = F::one(),
            Opcode::LOAD => self.is_load = F::one(),
            Opcode::STORE => self.is_store = F::one(),
            Opcode::BEQ => self.is_beq = F::one(),
            Opcode::BNE => self.is_bne = F::one(),
            Opcode::BNEINC => self.is_bneinc = F::one(),
            Opcode::JAL => self.is_jal = F::one(),
            Opcode::JALR => self.is_jalr = F::one(),
            Opcode::TRAP => self.is_trap = F::one(),
            Opcode::HALT => self.is_halt = F::one(),
            Opcode::FRIFold => self.is_fri_fold = F::one(),
            Opcode::ExpReverseBitsLen => self.is_exp_reverse_bits_len = F::one(),
            Opcode::Poseidon2Compress => self.is_poseidon = F::one(),
            Opcode::Commit => self.is_commit = F::one(),
            Opcode::HintExt2Felt => self.is_ext_to_felt = F::one(),

            Opcode::Hint
            | Opcode::HintBits
            | Opcode::PrintF
            | Opcode::PrintE
            | Opcode::RegisterPublicValue
            | Opcode::CycleTracker => {
                self.is_noop = F::one();
            }

            Opcode::HintLen | Opcode::LessThanF => {}
        }

        if matches!(
            instruction.opcode,
            Opcode::EADD | Opcode::ESUB | Opcode::EMUL | Opcode::EDIV
        ) {
            self.is_ext = F::one();
        }

        if instruction_is_heap_expand(instruction) {
            self.is_heap_expand = F::one();
        }
    }
}

impl<T: Copy> IntoIterator for &OpcodeSelectorCols<T> {
    type Item = T;

    type IntoIter = std::array::IntoIter<T, OPCODE_COUNT>;

    fn into_iter(self) -> Self::IntoIter {
        [
            self.is_add,
            self.is_sub,
            self.is_mul,
            self.is_div,
            self.is_ext,
            self.is_load,
            self.is_store,
            self.is_beq,
            self.is_bne,
            self.is_bneinc,
            self.is_jal,
            self.is_jalr,
            self.is_trap,
            self.is_halt,
            self.is_noop,
            self.is_poseidon,
            self.is_fri_fold,
            self.is_commit,
            self.is_ext_to_felt,
            self.is_exp_reverse_bits_len,
            self.is_heap_expand,
        ]
        .into_iter()
    }
}
