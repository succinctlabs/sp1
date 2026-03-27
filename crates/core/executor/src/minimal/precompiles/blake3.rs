use sp1_jit::SyscallContext;

/// Full Blake3 message schedule for 7 rounds.
/// Matches the official Blake3 reference: https://github.com/BLAKE3-team/BLAKE3
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// G_INDEX: for each of the 8 column operations in a round, the 4 state indices.
const G_INDEX: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
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

/// The Blake3 inner compress syscall for the minimal executor.
///
/// Arguments:
///   - `arg1` (a0): pointer to 16-word state array (in/out), each word at offset `i * 8`
///   - `arg2` (a1): pointer to 16-word message array (read-only), each word at offset `j * 8`
///
/// # Safety
/// - The memory in `ctx` is valid for the duration of the function call.
#[allow(clippy::pedantic)]
pub(crate) unsafe fn blake3_compress_inner(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let state_ptr = arg1;
    let msg_ptr = arg2;

    // Phase 1: Read the 16 state words.
    let mut state = [0u32; 16];
    for i in 0..16 {
        state[i] = ctx.mr(state_ptr + i as u64 * 8) as u32;
    }

    ctx.bump_memory_clk();

    // Phase 2: Read the 16 message words.
    let mut msg = [0u32; 16];
    for j in 0..16 {
        msg[j] = ctx.mr(msg_ptr + j as u64 * 8) as u32;
    }

    ctx.bump_memory_clk();

    // Compute Blake3 compression: 7 rounds of 8 G operations each.
    for round in 0..7 {
        for op in 0..8 {
            let [a, b, c, d] = G_INDEX[op];
            let mx = msg[MSG_SCHEDULE[round][2 * op]];
            let my = msg[MSG_SCHEDULE[round][2 * op + 1]];
            g(&mut state, a, b, c, d, mx, my);
        }
    }

    // Phase 3: Write the 16 state output words.
    for i in 0..16 {
        ctx.mw(state_ptr + i as u64 * 8, state[i] as u64);
    }

    None
}
