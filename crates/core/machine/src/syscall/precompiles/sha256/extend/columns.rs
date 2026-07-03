use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::{
    memory::MemoryAccessCols,
    operations::{
        Add4Operation, AddrAddOperation, ClkOperation, FixedRotateRightOperation,
        FixedShiftRightOperation, XorU32Operation,
    },
};

pub const NUM_SHA_EXTEND_COLS: usize = size_of::<ShaExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendCols<T> {
    /// Inputs.
    pub clk_high: T,
    pub clk_low: T,
    pub next_clk: ClkOperation<T>,
    pub w_ptr: [T; 3],
    pub w_i_minus_15_ptr: AddrAddOperation<T>,
    pub w_i_minus_2_ptr: AddrAddOperation<T>,
    pub w_i_minus_16_ptr: AddrAddOperation<T>,
    pub w_i_minus_7_ptr: AddrAddOperation<T>,
    pub w_i_ptr: AddrAddOperation<T>,

    /// Control flags.
    pub i: T,

    /// Inputs to `s0`.
    pub w_i_minus_15: MemoryAccessCols<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightOperation<T>,
    pub s0_intermediate: XorU32Operation<T>,

    /// `s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)`.
    pub s0: XorU32Operation<T>,

    /// Inputs to `s1`.
    pub w_i_minus_2: MemoryAccessCols<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightOperation<T>,
    pub s1_intermediate: XorU32Operation<T>,

    /// `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)`.
    pub s1: XorU32Operation<T>,

    /// Inputs to `s2`.
    pub w_i_minus_16: MemoryAccessCols<T>,
    pub w_i_minus_7: MemoryAccessCols<T>,

    /// `w[i] := w[i-16] + s0 + w[i-7] + s1`.
    pub s2: Add4Operation<T>,

    /// Result.
    pub w_i: MemoryAccessCols<T>,

    /// Selector.
    pub is_real: T,
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> ShaExtendCols<T> {
    /// Backend-agnostic witgen for ONE ShaExtend row (one `j ∈ 0..48` step of one
    /// SHA_EXTEND syscall). The chip is 48-rows-per-event but each row depends only
    /// on that row's memory records, so rows pack independently:
    /// `clk` is the BUMPED clock (`event.clk + 1`), `j` the step index, then the 4
    /// read records (value/prev_ts/ts — a read's prev value IS its value) and the
    /// `w_i` write record (prev_value/prev_ts/ts).
    ///
    /// Trapped events produce all-zero rows on host: the record fn wraps this in a
    /// `push_guard(is_real)` (suppresses lookups) and masks every column wire with
    /// `field_select(is_real, col, 0)` — see `record_sha_extend_program`.
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut ShaExtendCols<WB::Field>,
        clk: WB::Nat,
        w_ptr: WB::Nat,
        j: WB::Nat,
        w15_value: WB::Nat,
        w15_prev_ts: WB::Nat,
        w15_ts: WB::Nat,
        w2_value: WB::Nat,
        w2_prev_ts: WB::Nat,
        w2_ts: WB::Nat,
        w16_value: WB::Nat,
        w16_prev_ts: WB::Nat,
        w16_ts: WB::Nat,
        w7_value: WB::Nat,
        w7_prev_ts: WB::Nat,
        w7_ts: WB::Nat,
        wi_prev_value: WB::Nat,
        wi_prev_ts: WB::Nat,
        wi_ts: WB::Nat,
        is_real: WB::Nat,
    ) {
        use crate::operations::{
            Add4Operation, AddrAddOperation, ClkOperation, FixedRotateRightOperation,
            FixedShiftRightOperation, XorU32Operation,
        };
        use sp1_core_executor::ByteOpcode;

        let one = wb.const_nat(1);
        cols.is_real = wb.nat_to_field(is_real);
        let sixteen = wb.const_nat(16);
        let i = wb.wrapping_add(j, sixteen);
        cols.i = wb.nat_to_field(i);
        let clk_high = wb.bits(clk, 24, 32);
        cols.clk_high = wb.nat_to_field(clk_high);
        let clk_low = wb.bits(clk, 0, 24);
        cols.clk_low = wb.nat_to_field(clk_low);
        ClkOperation::<WB::Field>::witgen(wb, &mut cols.next_clk, clk, j);

        for k in 0..3 {
            let limb = wb.bits(w_ptr, 16 * k as u32, 16);
            cols.w_ptr[k] = wb.nat_to_field(limb);
        }
        // Pointer offsets: (i - {15,2,16,7,0}) * 8 with i = j + 16.
        let three = wb.const_nat(3);
        let mut ptr = |wb: &mut WB, cols_ptr: &mut AddrAddOperation<WB::Field>, delta: u64| {
            let d = wb.const_nat(delta);
            let idx = wb.wrapping_add(j, d);
            let off = wb.shl(idx, three);
            AddrAddOperation::<WB::Field>::witgen(wb, cols_ptr, w_ptr, off);
        };
        ptr(wb, &mut cols.w_i_minus_15_ptr, 1); // i - 15 = j + 1
        ptr(wb, &mut cols.w_i_minus_2_ptr, 14); // i - 2 = j + 14
        ptr(wb, &mut cols.w_i_minus_16_ptr, 0); // i - 16 = j
        ptr(wb, &mut cols.w_i_minus_7_ptr, 9); // i - 7 = j + 9
        ptr(wb, &mut cols.w_i_ptr, 16); // i = j + 16

        // Memory accesses (a read's previous value is its value).
        crate::memory::MemoryAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_15,
            w15_value,
            w15_prev_ts,
            w15_ts,
        );
        crate::memory::MemoryAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_2,
            w2_value,
            w2_prev_ts,
            w2_ts,
        );
        crate::memory::MemoryAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_16,
            w16_value,
            w16_prev_ts,
            w16_ts,
        );
        crate::memory::MemoryAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_7,
            w7_value,
            w7_prev_ts,
            w7_ts,
        );

        // s0 = (w15 >>> 7) ^ (w15 >>> 18) ^ (w15 >> 3).
        let w15 = wb.bits(w15_value, 0, 32);
        let rr7 = FixedRotateRightOperation::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_15_rr_7,
            w15,
            7,
        );
        let rr18 = FixedRotateRightOperation::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_15_rr_18,
            w15,
            18,
        );
        let rs3 = FixedShiftRightOperation::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_15_rs_3,
            w15,
            3,
        );
        let s0_int =
            XorU32Operation::<WB::Field>::witgen_xor_u32(wb, &mut cols.s0_intermediate, rr7, rr18);
        let s0 = XorU32Operation::<WB::Field>::witgen_xor_u32(wb, &mut cols.s0, s0_int, rs3);

        // s1 = (w2 >>> 17) ^ (w2 >>> 19) ^ (w2 >> 10).
        let w2 = wb.bits(w2_value, 0, 32);
        let rr17 = FixedRotateRightOperation::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_2_rr_17,
            w2,
            17,
        );
        let rr19 = FixedRotateRightOperation::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_2_rr_19,
            w2,
            19,
        );
        let rs10 = FixedShiftRightOperation::<WB::Field>::witgen(
            wb,
            &mut cols.w_i_minus_2_rs_10,
            w2,
            10,
        );
        let s1_int =
            XorU32Operation::<WB::Field>::witgen_xor_u32(wb, &mut cols.s1_intermediate, rr17, rr19);
        let s1 = XorU32Operation::<WB::Field>::witgen_xor_u32(wb, &mut cols.s1, s1_int, rs10);

        // w[i] = w[i-16] + s0 + w[i-7] + s1.
        let w16 = wb.bits(w16_value, 0, 32);
        let w7 = wb.bits(w7_value, 0, 32);
        Add4Operation::<WB::Field>::witgen(wb, &mut cols.s2, w16, s0, w7, s1);

        // The w_i write access.
        crate::memory::MemoryAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.w_i,
            wi_prev_value,
            wi_prev_ts,
            wi_ts,
        );

        // j < 48.
        let ltu = wb.const_nat(ByteOpcode::LTU as u64);
        let c48 = wb.const_nat(48);
        wb.add_byte_lookup(ltu, one, j, c48);
    }
}
