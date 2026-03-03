use crate::{
    memory::MemoryAccessCols,
    operations::{AddrAddOperation, AddU32Operation, FixedRotateRightOperation, XorU32Operation},
};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_BLAKE3_COMPRESS_COLS: usize = size_of::<Blake3CompressCols<u8>>();

/// Columns for the Blake3 compress chip.
///
/// Layout (104 rows per invocation):
///   - Rows   0–15:  state_init  — read state[i] from memory
///   - Rows  16–31:  msg_read    — read msg[j] from memory
///   - Rows  32–87:  compute     — one G function call per row (56 rows)
///   - Rows  88–103: finalize    — write state[i] to memory
///
/// The Blake3Compress interaction carries the full 16-word state at each row index,
/// linking the controller to the first and last rows, and linking successive rows.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3CompressCols<T> {
    // ── Identifiers ─────────────────────────────────────────────────────────
    /// High 24 bits of the syscall clock.
    pub clk_high: T,
    /// Low 24 bits of the syscall clock.
    pub clk_low: T,
    /// Pointer to the 16-word state array (three u16 limbs for 48-bit address).
    pub state_ptr: [T; 3],
    /// Pointer to the 16-word message array (three u16 limbs for 48-bit address).
    pub msg_ptr: [T; 3],
    /// Overall row index within this invocation (0..ROWS_PER_INVOCATION).
    pub index: T,

    // ── Phase selectors ──────────────────────────────────────────────────────
    /// True for rows 0–15 (state init).
    pub is_state_init: T,
    /// True for rows 16–31 (message read).
    pub is_msg_read: T,
    /// True for rows 32–87 (compute / G-function).
    pub is_compute: T,
    /// True for rows 88–103 (finalize / state write).
    pub is_finalize: T,

    /// One-hot selector for position within the 16-element init/finalize phases (0..16).
    pub phase_idx: [T; 16],

    // ── Compute-phase selectors ──────────────────────────────────────────────
    /// One-hot selector for the round index (0..7).
    pub round: [T; 7],
    /// One-hot selector for the operation index within a round (0..8).
    pub op: [T; 8],

    // ── State (all rows) ─────────────────────────────────────────────────────
    /// Full 16-word state, each word stored as two u16 limbs.
    /// On compute rows, this is the PRE-G-call state.
    pub state: [[T; 2]; 16],
    /// Full 16-word state AFTER the G call for this row (compute rows only).
    /// For non-compute rows, this is unused (zero-initialized).
    /// Degree-1 witness used in the Blake3Compress interaction send.
    pub next_state: [[T; 2]; 16],

    // ── Message (msg_read and compute rows) ──────────────────────────────────
    /// Full 16-word message, each word stored as two u16 limbs.
    pub msg: [[T; 2]; 16],

    // ── Memory access (init/msg_read/finalize rows, 1 access per row) ────────
    pub mem: MemoryAccessCols<T>,
    /// The effective memory address for this row (degree-1 witness for the interaction).
    /// Bound per-phase: state_init → mem_addr_state_init.value, etc.
    pub mem_addr: [T; 3],
    pub mem_addr_state_init: AddrAddOperation<T>,
    pub mem_addr_msg_read: AddrAddOperation<T>,
    pub mem_addr_finalize: AddrAddOperation<T>,
    /// The u32 memory word as two u16 limbs.
    pub mem_value: [T; 2],

    // ── Active G-function inputs (compute rows) ───────────────────────────────
    /// state[G_INDEX[op][0]] — first G input
    pub ga: [T; 2],
    /// state[G_INDEX[op][1]] — second G input
    pub gb: [T; 2],
    /// state[G_INDEX[op][2]] — third G input
    pub gc: [T; 2],
    /// state[G_INDEX[op][3]] — fourth G input
    pub gd: [T; 2],
    /// msg[MSG_SCHEDULE[round][2*op]] — first message word
    pub mx: [T; 2],
    /// msg[MSG_SCHEDULE[round][2*op+1]] — second message word
    pub my: [T; 2],

    // ── G function intermediate computations (compute rows) ───────────────────
    //
    // Step 1: a' = a + b + mx  (two chained adds)
    pub a_add_b: AddU32Operation<T>,
    pub a_add_b_add_mx: AddU32Operation<T>,
    // Step 2: d' = (d ^ a')
    pub d_xor_a: XorU32Operation<T>,
    // Step 3: d'' = d' rotr 16  — pure limb swap, no extra columns
    // Step 4: c' = c + d''
    pub c_add_d: AddU32Operation<T>,
    // Step 5: b' = b ^ c'
    pub b_xor_c: XorU32Operation<T>,
    /// u16 limbs of b_xor_c result (for rotr12 input — FixedRotateRight needs [T; 2] Vars)
    pub b_xor_c_limbs: [T; 2],
    // Step 6: b'' = b' rotr 12
    pub b_rotr12: FixedRotateRightOperation<T>,
    // Step 7: a'' = a' + b'' + my  (two chained adds)
    pub a2_add_b2: AddU32Operation<T>,
    pub a2_add_b2_add_my: AddU32Operation<T>,
    // Step 8: d''' = d'' ^ a''
    pub d_xor_a2: XorU32Operation<T>,
    /// u16 limbs of d_xor_a2 result (for rotr8 input)
    pub d_xor_a2_limbs: [T; 2],
    // Step 9: d'''' = d''' rotr 8
    pub d_rotr8: FixedRotateRightOperation<T>,
    // Step 10: c'' = c' + d''''
    pub c_add_d2: AddU32Operation<T>,
    // Step 11: b''' = b'' ^ c''
    pub b_xor_c2: XorU32Operation<T>,
    /// u16 limbs of b_xor_c2 result (for rotr7 input)
    pub b_xor_c2_limbs: [T; 2],
    // Step 12: b'''' = b''' rotr 7
    pub b_rotr7: FixedRotateRightOperation<T>,

    /// True if this row is a real (non-padding) row.
    pub is_real: T,
}
