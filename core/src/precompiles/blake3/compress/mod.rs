use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};

///! This module contains the implementation of the `blake3_compress_inner` precompile based on the
/// implementation of the `blake3` hash function in Plonky3.
mod air;
mod columns;
mod execute;
mod g;
mod trace;

/// The number of `Word`s in the state of the compress inner operation.
pub(crate) const STATE_SIZE: usize = 16;

/// The number of `Word`s in the message of the compress inner operation.
pub(crate) const MSG_SIZE: usize = 16;

/// The number of times we call `round` in the compress inner operation.
pub(crate) const ROUND_COUNT: usize = 7;

/// The number of times we call `g` in the compress inner operation.
pub(crate) const OPERATION_COUNT: usize = 8;

/// The number of `Word`s in the state that we pass to `g`.
pub(crate) const NUM_STATE_WORDS_PER_CALL: usize = 4;

/// The number of `Word`s in the message that we pass to `g`.
pub(crate) const NUM_MSG_WORDS_PER_CALL: usize = 2;

/// The number of `Word`s in the input of `g`.
pub(crate) const G_INPUT_SIZE: usize = NUM_MSG_WORDS_PER_CALL + NUM_STATE_WORDS_PER_CALL;

/// The number of `Word`s in the input of `compress`.
pub(crate) const INPUT_SIZE: usize = STATE_SIZE + MSG_SIZE;

/// The number of `Word`s to write after calling `g`.
pub(crate) const G_OUTPUT_SIZE: usize = NUM_STATE_WORDS_PER_CALL;

pub(crate) const MSG_SCHEDULE: [[usize; MSG_SIZE]; ROUND_COUNT] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// The `i`-th row of `G_INDEX` is the indices used for the `i`-th call to `g`.
pub(crate) const G_INDEX: [[usize; NUM_STATE_WORDS_PER_CALL]; OPERATION_COUNT] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

#[derive(Debug, Clone, Copy)]
pub struct Blake3CompressInnerEvent {
    pub clk: u32,
    pub segment: u32,
    pub state_ptr: u32,
    pub reads: [[[MemoryReadRecord; G_INPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT],
    pub writes: [[[MemoryWriteRecord; G_OUTPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT],
}

pub struct Blake3CompressInnerChip {}

impl Blake3CompressInnerChip {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
    use crate::runtime::Syscall;
    use crate::utils::prove;
    use crate::utils::setup_logger;
    use crate::Program;

    use super::INPUT_SIZE;

    pub fn blake3_compress_internal_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![];

        for i in 0..INPUT_SIZE {
            // Store 1000 + i in memory for the i-th word of the state. 1000 + i is an arbitrary
            // number that is easy to spot while debugging.
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, 1000 + i as u32, false, true),
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i as u32 * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                Syscall::BLAKE3_COMPRESS_INNER as u32,
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
        let program = blake3_compress_internal_program();
        prove(program);
    }

    // TODO: Create something like this for blake3.
    // #[test]
    // fn test_poseidon2_external_1_simple() {
    //     setup_logger();
    //     let program = Program::from(POSEIDON2_EXTERNAL_1_ELF);
    //     prove(program);
    // }
}
