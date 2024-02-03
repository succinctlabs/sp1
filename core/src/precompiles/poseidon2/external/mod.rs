use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};

use self::columns::POSEIDON2_DEFAULT_EXTERNAL_ROUNDS;

mod air;
mod columns;
mod execute;
mod trace;

// TODO: Make sure that I'm only adding columns that I need. I just copied and pasted these from SHA
// compress as a starting point, so these likely need to change quite a bit.
#[derive(Debug, Clone, Copy)]
pub struct Poseidon2ExternalEvent<const N: usize> {
    pub clk: u32,
    pub state_ptr: u32,
    pub state_reads: [[MemoryReadRecord; N]; POSEIDON2_DEFAULT_EXTERNAL_ROUNDS],
    pub state_writes: [[MemoryWriteRecord; N]; POSEIDON2_DEFAULT_EXTERNAL_ROUNDS],
}

pub struct Poseidon2ExternalChip<const N: usize>;

impl<const N: usize> Poseidon2ExternalChip<N> {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod external_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, Runtime, Syscall},
        utils::{ec::NUM_WORDS_FIELD_ELEMENT, prove, setup_logger, BabyBearPoseidon2, StarkUtils},
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
