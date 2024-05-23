//! This module contains the implementation of the `blake3_compress_inner` precompile based on the
//! implementation of the `blake3` hash function in BLAKE3.
//!
//! Pseudo-code.
//!
//! state = [0u32; 16]
//! message = [0u32; 16]
//!
//! for round in 0..7 {
//!    for operation in 0..8 {
//!       // * Pick 4 indices a, b, c, d for the state, based on the operation index.
//!       // * Pick 2 indices x, y for the message, based on both the round and the operation index.
//!       //
//!       // g takes those 6 values, and updates the 4 state values, at indices a, b, c, d.
//!       //
//!       // Each call of g becomes one row in the trace.
//!       g(&mut state[a], &mut state[b], &mut state[c], &mut state[d], message[x], message[y]);
//!   }
//! }
//!
//! Note that this precompile is only the blake3 compress inner function. The Blake3 compress
//! function has a series of 8 XOR operations after the compress inner function.
mod air;
mod columns;
mod execute;
mod g;
mod trace;
use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

use serde::{Deserialize, Serialize};

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

/// 2-dimensional array specifying which message values `g` should access. Values at `(i, 2 * j)`
/// and `(i, 2 * j + 1)` are the indices of the message values that `g` should access in the `j`-th
/// call of the `i`-th round.
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

pub(crate) const fn g_func(input: [u32; 6]) -> [u32; 4] {
    let mut a = input[0];
    let mut b = input[1];
    let mut c = input[2];
    let mut d = input[3];
    let x = input[4];
    let y = input[5];
    a = a.wrapping_add(b).wrapping_add(x);
    d = (d ^ a).rotate_right(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(12);
    a = a.wrapping_add(b).wrapping_add(y);
    d = (d ^ a).rotate_right(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(7);
    [a, b, c, d]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake3CompressInnerEvent {
    pub clk: u32,
    pub shard: u32,
    pub channel: u32,
    pub state_ptr: u32,
    pub message_ptr: u32,
    pub message_reads: [[[MemoryReadRecord; NUM_MSG_WORDS_PER_CALL]; OPERATION_COUNT]; ROUND_COUNT],
    pub state_writes:
        [[[MemoryWriteRecord; NUM_STATE_WORDS_PER_CALL]; OPERATION_COUNT]; ROUND_COUNT],
}

pub struct Blake3CompressInnerChip {}

impl Blake3CompressInnerChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
    use crate::runtime::Register;
    use crate::runtime::SyscallCode;
    use crate::Program;

    use super::MSG_SIZE;

    /// The number of `Word`s in the state of the compress inner operation.
    const STATE_SIZE: usize = 16;

    pub fn blake3_compress_internal_program() -> Program {
        let state_ptr = 100;
        let msg_ptr = 500;
        let mut instructions = vec![];

        for i in 0..STATE_SIZE {
            // Store 1000 + i in memory for the i-th word of the state. 1000 + i is an arbitrary
            // number that is easy to spot while debugging.
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, 1000 + i as u32, false, true),
                Instruction::new(Opcode::ADD, 30, 0, state_ptr + i as u32 * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        for i in 0..MSG_SIZE {
            // Store 2000 + i in memory for the i-th word of the message. 2000 + i is an arbitrary
            // number that is easy to spot while debugging.
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, 2000 + i as u32, false, true),
                Instruction::new(Opcode::ADD, 30, 0, msg_ptr + i as u32 * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::BLAKE3_COMPRESS_INNER as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, Register::X10 as u32, 0, state_ptr, false, true),
            Instruction::new(Opcode::ADD, Register::X11 as u32, 0, msg_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    // Tests disabled because syscall is not enabled in default runtime/chip configs.
    // #[test]
    // fn prove_babybear() {
    //     setup_logger();
    //     let program = blake3_compress_internal_program();
    //     run_test(program).unwrap();
    // }

    // #[test]
    // fn test_blake3_compress_inner_elf() {
    //     setup_logger();
    //     let program = Program::from(BLAKE3_COMPRESS_ELF);
    //     run_test(program).unwrap();
    // }
}
