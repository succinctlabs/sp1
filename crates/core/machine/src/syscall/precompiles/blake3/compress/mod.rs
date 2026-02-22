mod air;
pub mod columns;
mod controller;
mod trace;

/// Blake3 message schedule permutation.
pub const MSG_PERMUTATION: [usize; 16] =
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Full Blake3 message schedule for 7 rounds. Each row is a permutation of 0..16.
///
/// `MSG_SCHEDULE[r][i]` gives the message word index used at position `i` in round `r`.
/// For G call (round=r, op=o): mx = msg[MSG_SCHEDULE[r][2*o]], my = msg[MSG_SCHEDULE[r][2*o+1]].
pub const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 12, 13, 14, 6, 3, 4, 11, 0, 7, 9, 2, 8, 5, 1, 15],
    [6, 5, 9, 8, 2, 10, 13, 0, 4, 3, 7, 14, 11, 1, 12, 15],
    [2, 3, 4, 14, 6, 5, 7, 11, 10, 8, 9, 1, 13, 12, 0, 15],
    [12, 8, 9, 5, 11, 6, 14, 0, 2, 3, 7, 4, 13, 10, 1, 15],
];

/// For each of the 8 operations per round, the 4 state word indices involved.
pub const G_INDEX: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// Number of rounds in Blake3 compression.
pub const ROUND_COUNT: usize = 7;

/// Number of G operations per round.
pub const OPERATION_COUNT: usize = 8;

/// Total number of G calls per compress invocation.
pub const TOTAL_G_CALLS: usize = ROUND_COUNT * OPERATION_COUNT; // 56

/// Rows for state init phase (reading state from memory).
pub const STATE_INIT_ROWS: usize = 16;

/// Rows for message read phase (reading message from memory).
pub const MSG_READ_ROWS: usize = 16;

/// Rows for the compute phase (one row per G call).
pub const COMPUTE_ROWS: usize = TOTAL_G_CALLS; // 56

/// Rows for the finalize phase (writing state to memory).
pub const FINALIZE_ROWS: usize = 16;

/// Total rows per Blake3 compress invocation.
pub const ROWS_PER_INVOCATION: usize =
    STATE_INIT_ROWS + MSG_READ_ROWS + COMPUTE_ROWS + FINALIZE_ROWS; // 104

/// Row index where the state init phase starts.
pub const STATE_INIT_START: usize = 0;

/// Row index where the message read phase starts.
pub const MSG_READ_START: usize = STATE_INIT_START + STATE_INIT_ROWS; // 16

/// Row index where the compute phase starts.
pub const COMPUTE_START: usize = MSG_READ_START + MSG_READ_ROWS; // 32

/// Row index where the finalize phase starts.
pub const FINALIZE_START: usize = COMPUTE_START + COMPUTE_ROWS; // 88

/// The Blake3 compress chip, which processes one G-function call per row.
#[derive(Default)]
pub struct Blake3CompressChip;

impl Blake3CompressChip {
    pub const fn new() -> Self {
        Self {}
    }
}

/// The controller chip for Blake3 compress, which receives syscalls and routes them.
#[derive(Default)]
pub struct Blake3CompressControlChip;

#[cfg(test)]
pub mod compress_tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::BLAKE3_COMPRESS_ELF;

    use crate::{
        io::SP1Stdin,
        utils::{run_test, setup_logger},
    };

    use super::{G_INDEX, MSG_SCHEDULE};

    /// Blake3 IV constants.
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    /// Reference Blake3 compress_inner using the same MSG_SCHEDULE as the machine chip.
    fn blake3_compress_inner_ref(state: &mut [u32; 16], msg: &[u32; 16]) {
        for round in 0..7 {
            for op in 0..8 {
                let [a, b, c, d] = G_INDEX[op];
                let mx = msg[MSG_SCHEDULE[round][2 * op]];
                let my = msg[MSG_SCHEDULE[round][2 * op + 1]];
                g(state, a, b, c, d, mx, my);
            }
        }
    }

    #[tokio::test]
    async fn test_blake3_compress_program() {
        setup_logger();
        let program = Arc::new(Program::from(&BLAKE3_COMPRESS_ELF).unwrap());
        let stdin = SP1Stdin::new();
        let mut public_values = run_test(program, stdin).await.unwrap();

        // Deserialize the committed state from the guest.
        let proven_state = public_values.read::<[u64; 16]>();

        // Reproduce the same computation natively with the reference implementation.
        let mut ref_state: [u32; 16] = [
            IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7],
            IV[0], IV[1], IV[2], IV[3], 0, 0, 64, 11,
        ];
        let msg: [u32; 16] = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
            0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
            0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f,
            0x30313233, 0x34353637, 0x38393a3b, 0x3c3d3e3f,
        ];
        for _ in 0..4 {
            blake3_compress_inner_ref(&mut ref_state, &msg);
        }

        // The guest stores each u32 word in the lower 32 bits of a u64 slot.
        for i in 0..16 {
            assert_eq!(
                proven_state[i] as u32,
                ref_state[i],
                "state[{i}] mismatch: proven={:#010x} expected={:#010x}",
                proven_state[i] as u32,
                ref_state[i],
            );
        }
    }
}
