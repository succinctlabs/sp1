//! This module contains the implementation of the `blake2b inner compress` precompile based on
//! the implementation of the `blake2b` hash function in BLAKE2.
//!
//! Pseudo-code.
//!
//! state = [0u64; 16]
//! message_chunk = [0u64; 16]
//!
//! for round in 0..12 {
//!     for operation in 0..8 {
//!         // * Pick 4 indices a, b, c, d for the state, based on the operation index.
//!         // * Pick 2 indices x, y for the message, based on both the round and the operation index.
//!         //
//!         // g takes those 6 values, and updates the 4 state values, at indices a, b, c, d.
//!         //
//!         // Each call of mix becomes one row in the trace.
//!         mix(&mut state[a], &mut state[b], &mut state[c], &mut state[d], message[x], message[y]);
//!     }
//! }
use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};
mod air;
mod columns;
mod execute;
mod mix;
mod trace;

/// The number of `u64`s in the message of the compress inner operation.
pub(crate) const MSG_SIZE: usize = 16;

/// Each msg word is 8 bytes and our words size is 4 bytes. So we need to double the size of the
/// message.
#[allow(dead_code)]
pub(crate) const MSG_NUM_WORDS: usize = MSG_SIZE * 2;

/// The number of rounds in the compress inner operation.
pub(crate) const NUM_MIX_ROUNDS: usize = 12;

/// The number of time we call `mix` in the compress inner operation in each mix round.
pub(crate) const OPERATION_COUNT: usize = 8;

/// The number of `Word`s in the state that we pass to `mix`. Each `Word` is 8 bytes.
pub(crate) const STATE_ELE_PER_CALL: usize = 4;

/// Each state word is 8 bytes and our words size is 4 bytes. So we need to double the size of the
/// state.
pub(crate) const NUM_STATE_WORDS_PER_CALL: usize = STATE_ELE_PER_CALL * 2;

/// The number of `Word`s in the message that we pass to `mix`. Each `Word` is 8 bytes.
pub(crate) const MSG_ELE_PER_CALL: usize = 2;

/// Each message word is 8 bytes and our words size is 4 bytes. So we need to double the size of the
/// message.
pub(crate) const NUM_MSG_WORDS_PER_CALL: usize = MSG_ELE_PER_CALL * 2;

/// The number of `Word`s in the input of `mix`.
pub(crate) const MIX_INPUT_SIZE: usize = STATE_ELE_PER_CALL + MSG_ELE_PER_CALL;

/// The `i`-th row of `MIX_INDEX` is the indices used for the `i`-th call to `mix` in each round.
pub(crate) const MIX_INDEX: [[usize; STATE_ELE_PER_CALL]; OPERATION_COUNT] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// 2-dimensional array specifying which message values `mix` should access during each mix round.
/// Values at `(i, 2 * j)` and `(i, 2 * j + 1)` are the indices of the message values that `mix`
/// should access in the `j`-th call of the `i`-th round. Note that 11th and 12th rounds values
/// are the same as the 0th and 1st rounds.
pub(crate) const SIGMA_PERMUTATIONS: [[usize; MSG_SIZE]; NUM_MIX_ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 15, 10, 14, 13, 0, 11, 3, 9, 7, 6, 4, 1, 2, 8],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
pub(crate) fn mix(input: [u64; MIX_INPUT_SIZE]) -> [u64; STATE_ELE_PER_CALL] {
    let mut a = input[0];
    let mut b = input[1];
    let mut c = input[2];
    let mut d = input[3];
    let x = input[4];
    let y = input[5];

    a = a.wrapping_add(b).wrapping_add(x);
    d = (d ^ a).rotate_right(32);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(24);
    a = a.wrapping_add(b).wrapping_add(y);
    d = (d ^ a).rotate_right(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(63);

    [a, b, c, d]
}

#[derive(Debug, Clone, Copy)]
pub struct Blake2bCompressInnerEvent {
    pub clk: u32,
    pub shard: u32,
    pub state_ptr: u32,
    pub message_ptr: u32,
    pub message_reads:
        [[[MemoryReadRecord; NUM_MSG_WORDS_PER_CALL]; OPERATION_COUNT]; NUM_MIX_ROUNDS],
    pub state_writes:
        [[[MemoryWriteRecord; NUM_STATE_WORDS_PER_CALL]; OPERATION_COUNT]; NUM_MIX_ROUNDS],
}

pub struct Blake2bCompressInnerChip {}

impl Blake2bCompressInnerChip {
    pub fn new() -> Self {
        Self {}
    }
}
