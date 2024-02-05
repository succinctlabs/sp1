use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    utils::ec::NUM_WORDS_FIELD_ELEMENT,
};

use self::columns::POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS;

mod add_rc;
mod air;
mod columns;
mod execute;
mod trace;

/// The number of words in the state that is used for the Poseidon2 precompile.
///
/// Ideally, this would be const generic, but AlignedBorrow doesn't accept a struct with two const
/// generics. Maybe there's a more elegant way of going about this, but also I think I should get
/// the precompile to work first with this const and from there I can think about that.
/// TODO: Revisit this to see if there's a different option.
/// TODO: Remove the const generic for this since it's not very useful if we define a const.
pub const NUM_LIMBS_POSEIDON2_STATE: usize = NUM_WORDS_FIELD_ELEMENT;

#[derive(Debug, Clone, Copy)]
pub struct Poseidon2ExternalEvent<const NUM_WORDS_STATE: usize> {
    pub clk: u32,
    pub state_ptr: u32,
    pub state_reads: [[MemoryReadRecord; NUM_WORDS_STATE]; POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS],
    pub state_writes:
        [[MemoryWriteRecord; NUM_WORDS_STATE]; POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS],
}

pub struct Poseidon2ExternalChip<const NUM_WORDS_STATE: usize>;

impl<const NUM_WORDS_STATE: usize> Poseidon2ExternalChip<NUM_WORDS_STATE> {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod external_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, Syscall},
        utils::{ec::NUM_WORDS_FIELD_ELEMENT, prove, setup_logger},
    };

    pub fn poseidon2_external_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![];
        for i in 0..NUM_WORDS_FIELD_ELEMENT {
            // Store 100 + i in memory for the i-th word of the state. 100 + i is an arbitrary
            // number that might be easy to stop while debugging.
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, 100 + i as u32, false, true),
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i as u32 * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                Syscall::POSEIDON2_EXTERNAL as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = poseidon2_external_program();
        prove(program);
    }
}
