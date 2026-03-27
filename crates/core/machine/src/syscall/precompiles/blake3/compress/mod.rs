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
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
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

/// Implements the Blake3 `compress_inner` operation.
///
/// The syscall takes a pointer to a 16-word state array and a pointer to a 16-word message array.
/// The state is updated in-place with the result of 7 rounds of 8 G-function calls each (56 total).
///
/// In the AIR, each Blake3 compress syscall occupies [`ROWS_PER_INVOCATION`] = 104 rows:
/// - Rows   0–15:  state init — read `state[0..16]` from memory
/// - Rows  16–31:  message read — read `msg[0..16]` from memory
/// - Rows  32–87:  compute — one G-function call per row (56 rows across 7 rounds × 8 ops)
/// - Rows  88–103: finalize — write the post-compression `state[0..16]` back to memory
///
/// Each memory word is a u32 stored in a u64 slot (upper 32 bits zero), represented in the AIR
/// as two u16 half-words.
#[derive(Default)]
pub struct Blake3CompressChip;

impl Blake3CompressChip {
    pub const fn new() -> Self {
        Self {}
    }
}

/// Controller chip for the Blake3 compress precompile.
///
/// Receives the `BLAKE3_COMPRESS_INNER` syscall from the CPU, validates the two memory pointers,
/// and sends/receives the initial and final states on the [`InteractionKind::Blake3Compress`] bus
/// to be consumed by [`Blake3CompressChip`].
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

    // ── Independent reference implementation ────────────────────────────────
    // Constants hardcoded directly from the Blake3 spec — NOT imported from the
    // machine chip.  Any divergence between this table and the chip's table will
    // be caught by test_compress_vs_blake3_crate below.

    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    // Blake3 G-function column/diagonal index table (spec §2.1).
    const G_INDEX_REF: [[usize; 4]; 8] = [
        [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
        [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14],
    ];

    // Blake3 message schedule — 7 rounds × 16 indices (spec §2.1 / reference_impl.rs).
    // Independently verified against the `blake3` crate source and the formula
    // schedule[r][j] = schedule[r-1][PERM[j]] where
    // PERM = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8].
    const MSG_SCHEDULE_REF: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    fn g_ref(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn compress_inner_ref(state: &mut [u32; 16], msg: &[u32; 16]) {
        for round in 0..7 {
            for op in 0..8 {
                let [a, b, c, d] = G_INDEX_REF[op];
                let mx = msg[MSG_SCHEDULE_REF[round][2 * op]];
                let my = msg[MSG_SCHEDULE_REF[round][2 * op + 1]];
                g_ref(state, a, b, c, d, mx, my);
            }
        }
    }

    // ── Fast unit tests (no proof, no executor) ──────────────────────────────

    /// Verify MSG_SCHEDULE_REF matches the formula schedule[r][j] = schedule[r-1][PERM[j]].
    /// This independently confirms the constant is self-consistent with the Blake3 permutation.
    #[test]
    fn test_msg_schedule_formula() {
        const PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
        let mut derived = [[0usize; 16]; 7];
        for j in 0..16 { derived[0][j] = j; }
        for r in 1..7 {
            for j in 0..16 {
                derived[r][j] = derived[r - 1][PERM[j]];
            }
        }
        assert_eq!(derived, MSG_SCHEDULE_REF, "MSG_SCHEDULE_REF doesn't match permutation formula");
    }

    /// Cross-check compress_inner_ref against the `blake3` crate for several inputs.
    ///
    /// For a single 64-byte block the Blake3 hash equals:
    ///   [state_out[i] ^ state_out[i+8] for i in 0..8]  encoded as little-endian bytes
    /// where state_out = compress_inner(state_init, msg_words) with
    ///   state_init = [cv[0..8], IV[0..4], counter_lo, counter_hi, block_len, flags].
    ///
    /// Using chaining_value = IV, counter = 0, flags = CHUNK_START|CHUNK_END|ROOT = 1|2|8 = 11
    /// this is exactly blake3::hash(&block_bytes).
    #[test]
    fn test_compress_vs_blake3_crate() {
        let test_cases: &[&[u8; 64]] = &[
            &[0u8; 64],
            &[0xFF; 64],
            &{
                let mut b = [0u8; 64];
                for (i, v) in b.iter_mut().enumerate() { *v = i as u8; }
                b
            },
            &{
                let mut b = [0u8; 64];
                for (i, v) in b.iter_mut().enumerate() { *v = (i * 7 + 3) as u8; }
                b
            },
        ];

        for (case_idx, block_bytes) in test_cases.iter().enumerate() {
            // Parse block as little-endian u32 words.
            let msg: [u32; 16] = std::array::from_fn(|i| {
                u32::from_le_bytes(block_bytes[i * 4..(i + 1) * 4].try_into().unwrap())
            });

            // State init: chaining_value = IV, counter = 0, flags = 11.
            let mut state: [u32; 16] = [
                IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7],
                IV[0], IV[1], IV[2], IV[3],
                0, 0, 64, 11, // counter_lo, counter_hi, block_len, CHUNK_START|CHUNK_END|ROOT
            ];

            compress_inner_ref(&mut state, &msg);

            // Output = XOR of two halves, encoded as LE bytes.
            let mut our_output = [0u8; 32];
            for i in 0..8 {
                let word = state[i] ^ state[i + 8];
                our_output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
            }

            let expected = blake3::hash(block_bytes.as_slice());
            assert_eq!(
                our_output,
                *expected.as_bytes(),
                "case {case_idx}: compress_inner_ref output doesn't match blake3::hash",
            );
        }
    }

    /// Confirm the machine chip's MSG_SCHEDULE constant matches MSG_SCHEDULE_REF.
    /// This ensures any accidental edit to compress/mod.rs is caught immediately.
    #[test]
    fn test_chip_msg_schedule_matches_spec() {
        use super::MSG_SCHEDULE as CHIP_SCHEDULE;
        assert_eq!(
            CHIP_SCHEDULE, MSG_SCHEDULE_REF,
            "machine chip MSG_SCHEDULE diverges from Blake3 spec"
        );
    }

    // ── Full proof test ───────────────────────────────────────────────────────

    /// End-to-end test: prove the Blake3 compress guest program and verify the
    /// committed output matches the independent reference implementation.
    #[tokio::test]
    async fn test_blake3_compress_program() {
        setup_logger();
        let program = Arc::new(Program::from(&BLAKE3_COMPRESS_ELF).unwrap());
        let stdin = SP1Stdin::new();
        let mut public_values = run_test(program, stdin).await.unwrap();

        let proven_state = public_values.read::<[u64; 16]>();

        // Same inputs as the guest program.
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
            compress_inner_ref(&mut ref_state, &msg);
        }

        for i in 0..16 {
            assert_eq!(
                proven_state[i] as u32, ref_state[i],
                "state[{i}] mismatch: proven={:#010x} expected={:#010x}",
                proven_state[i] as u32, ref_state[i],
            );
        }
    }
}
