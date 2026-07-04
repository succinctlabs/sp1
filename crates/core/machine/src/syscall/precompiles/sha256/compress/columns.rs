use crate::{
    memory::MemoryAccessCols,
    operations::{
        Add5Operation, AddU32Operation, AddrAddOperation, AndU32Operation,
        FixedRotateRightOperation, NotU32Operation, XorU32Operation,
    },
};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_SHA_COMPRESS_COLS: usize = size_of::<ShaCompressCols<u8>>();

/// A set of columns needed to compute the SHA-256 compression function.
///
/// Each sha compress syscall is processed over 80 columns, split into 10 octets. The first octet is
/// for initialization, the next 8 octets are for compression, and the last octet is for finalize.
/// During init, the columns are initialized with the input values, one word at a time. During each
/// compression cycle, one iteration of sha compress is computed. During finalize, the columns are
/// combined and written back to memory.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaCompressCols<T> {
    /// Inputs.
    pub clk_high: T,
    pub clk_low: T,
    pub w_ptr: [T; 3],
    pub h_ptr: [T; 3],

    pub index: T,

    /// Which cycle within the octet we are currently processing.
    pub octet: [T; 8],

    /// This will specify which octet we are currently processing.
    ///  - The first octet is for initialize.
    ///  - The next 8 octets are for compress.
    ///  - The last octet is for finalize.
    pub octet_num: [T; 10],

    /// Memory access. During init and compression, this is read only. During finalize, this is
    /// used to write the result into memory.
    pub mem: MemoryAccessCols<T>,

    /// The write value to the memory.
    pub mem_value: [T; 2],

    /// Current memory address being written/read. During init and finalize, this is A-H. During
    /// compression, this is w[i] being read only.
    pub mem_addr: [T; 3],

    pub mem_addr_init: AddrAddOperation<T>,
    pub mem_addr_compress: AddrAddOperation<T>,
    pub mem_addr_finalize: AddrAddOperation<T>,

    pub a: [T; 2],
    pub b: [T; 2],
    pub c: [T; 2],
    pub d: [T; 2],
    pub e: [T; 2],
    pub f: [T; 2],
    pub g: [T; 2],
    pub h: [T; 2],

    /// Current value of K[i]. This is a constant array that loops around every 64 iterations.
    pub k: [T; 2],

    pub e_rr_6: FixedRotateRightOperation<T>,
    pub e_rr_11: FixedRotateRightOperation<T>,
    pub e_rr_25: FixedRotateRightOperation<T>,
    pub s1_intermediate: XorU32Operation<T>,
    /// `S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)`.
    pub s1: XorU32Operation<T>,

    pub e_and_f: AndU32Operation<T>,
    pub e_not: NotU32Operation<T>,
    pub e_not_and_g: AndU32Operation<T>,
    /// `ch := (e and f) xor ((not e) and g)`.
    pub ch: XorU32Operation<T>,

    /// `temp1 := h + S1 + ch + k[i] + w[i]`.
    pub temp1: Add5Operation<T>,

    pub a_rr_2: FixedRotateRightOperation<T>,
    pub a_rr_13: FixedRotateRightOperation<T>,
    pub a_rr_22: FixedRotateRightOperation<T>,
    pub s0_intermediate: XorU32Operation<T>,
    /// `S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)`.
    pub s0: XorU32Operation<T>,

    pub a_and_b: AndU32Operation<T>,
    pub a_and_c: AndU32Operation<T>,
    pub b_and_c: AndU32Operation<T>,
    pub maj_intermediate: XorU32Operation<T>,
    /// `maj := (a and b) xor (a and c) xor (b and c)`.
    pub maj: XorU32Operation<T>,

    /// `temp2 := S0 + maj`.
    pub temp2: AddU32Operation<T>,

    /// The next value of `e` is `d + temp1`.
    pub d_add_temp1: AddU32Operation<T>,
    /// The next value of `a` is `temp1 + temp2`.
    pub temp1_add_temp2: AddU32Operation<T>,

    /// During finalize, this is one of a-h and is being written into `mem`.
    pub finalized_operand: [T; 2],
    pub finalize_add: AddU32Operation<T>,

    pub is_initialize: T,
    pub is_compression: T,
    pub is_finalize: T,

    pub is_real: T,
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> ShaCompressCols<T> {
    /// Backend-agnostic witgen for ONE ShaCompress row. The chip is
    /// 80-rows-per-event with three phases (8 init / 64 compress / 8 finalize) and
    /// working variables threaded across the compression rows; the device port
    /// resolves BOTH at pack time: the packer re-runs the compression host-side and
    /// hands every row its own `a..h`, phase-appropriate memory record, `w[j]`,
    /// `K[j]`, and finalize operands — so rows are independent.
    ///
    /// The phase (init/compress/finalize) is derived in-DAG from `index`
    /// (`octet_num = index >> 3`). Inactive phases' gadgets run on zero-masked
    /// inputs (yielding their all-zero default columns, matching the host's
    /// untouched zeroed rows) with lookups guarded per-phase. The `octet`,
    /// `octet_num`, `index` and `k` columns are computed UNGUARDED — trapped
    /// events' rows (and padding rows) keep them; the record fn masks every other
    /// column by `is_real` (see the exempt ranges in `record_sha_compress_program`).
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder<Field = T>>(
        wb: &mut WB,
        cols: &mut ShaCompressCols<T>,
        clk: WB::Nat,
        w_ptr: WB::Nat,
        h_ptr: WB::Nat,
        index: WB::Nat,
        k_val: WB::Nat,
        mem_prev_value: WB::Nat,
        mem_prev_ts: WB::Nat,
        mem_ts: WB::Nat,
        mem_value: WB::Nat,
        a: WB::Nat,
        b: WB::Nat,
        c: WB::Nat,
        d: WB::Nat,
        e: WB::Nat,
        f: WB::Nat,
        g: WB::Nat,
        h: WB::Nat,
        w_j: WB::Nat,
        og_h_j: WB::Nat,
        final_h_j: WB::Nat,
        is_real: WB::Nat,
    ) {
        use crate::memory::MemoryAccessCols;
        use crate::operations::{
            Add5Operation, AddU32Operation, AddrAddOperation, AndU32Operation,
            FixedRotateRightOperation, NotU32Operation, XorU32Operation,
        };

        let zero = wb.const_nat(0);
        let zero_f = wb.nat_to_field(zero);
        let one = wb.const_nat(1);

        cols.is_real = wb.nat_to_field(is_real);
        let clk_high = wb.bits(clk, 24, 32);
        cols.clk_high = wb.nat_to_field(clk_high);
        let clk_low = wb.bits(clk, 0, 24);
        cols.clk_low = wb.nat_to_field(clk_low);
        for i in 0..3 {
            let limb = wb.bits(w_ptr, 16 * i as u32, 16);
            cols.w_ptr[i] = wb.nat_to_field(limb);
            let limb = wb.bits(h_ptr, 16 * i as u32, 16);
            cols.h_ptr[i] = wb.nat_to_field(limb);
        }

        // Phase / cycle decomposition: octet_num = index >> 3, octet = index & 7.
        cols.index = wb.nat_to_field(index);
        let oct_num = wb.bits(index, 3, 4);
        let oct = wb.bits(index, 0, 3);
        for kk in 0..8u64 {
            let kkw = wb.const_nat(kk);
            let flag = wb.eq(oct, kkw);
            cols.octet[kk as usize] = wb.nat_to_field(flag);
        }
        for kk in 0..10u64 {
            let kkw = wb.const_nat(kk);
            let flag = wb.eq(oct_num, kkw);
            cols.octet_num[kk as usize] = wb.nat_to_field(flag);
        }
        let is_init = wb.eq(oct_num, zero);
        let nine = wb.const_nat(9);
        let is_fin = wb.eq(oct_num, nine);
        let init_or_fin = wb.wrapping_add(is_init, is_fin);
        let is_comp = wb.eq(init_or_fin, zero);
        cols.is_initialize = wb.nat_to_field(is_init);
        cols.is_compression = wb.nat_to_field(is_comp);
        cols.is_finalize = wb.nat_to_field(is_fin);

        // K[index] column (packed; zero outside compression, matching the host).
        let k0 = wb.bits(k_val, 0, 16);
        let k1 = wb.bits(k_val, 16, 16);
        cols.k = [wb.nat_to_field(k0), wb.nat_to_field(k1)];

        // Memory access (every row reads or writes one word).
        MemoryAccessCols::<T>::witgen(wb, &mut cols.mem, mem_prev_value, mem_prev_ts, mem_ts);
        let mv0 = wb.bits(mem_value, 0, 16);
        let mv1 = wb.bits(mem_value, 16, 16);
        cols.mem_value = [wb.nat_to_field(mv0), wb.nat_to_field(mv1)];

        // Per-phase address gadgets (inactive ones on zero inputs = all-zero cols).
        let three = wb.const_nat(3);
        let eight = wb.const_nat(8);
        let seventy_two = wb.const_nat(72);
        let off_init = wb.shl(index, three);
        let idx_c = wb.wrapping_sub(index, eight);
        let off_comp = wb.shl(idx_c, three);
        let idx_f = wb.wrapping_sub(index, seventy_two);
        let off_fin = wb.shl(idx_f, three);
        let addr_gadget = |wb: &mut WB,
                               gcols: &mut AddrAddOperation<T>,
                               phase: WB::Nat,
                               ptr: WB::Nat,
                               off: WB::Nat| {
            let p = wb.select(phase, ptr, zero);
            let o = wb.select(phase, off, zero);
            wb.push_guard(phase);
            AddrAddOperation::<T>::witgen(wb, gcols, p, o);
            wb.pop_guard();
        };
        addr_gadget(wb, &mut cols.mem_addr_init, is_init, h_ptr, off_init);
        addr_gadget(wb, &mut cols.mem_addr_compress, is_comp, w_ptr, off_comp);
        addr_gadget(wb, &mut cols.mem_addr_finalize, is_fin, h_ptr, off_fin);
        for i in 0..3 {
            let s = wb.field_add(cols.mem_addr_init.value[i], cols.mem_addr_compress.value[i]);
            cols.mem_addr[i] = wb.field_add(s, cols.mem_addr_finalize.value[i]);
        }

        // Working variables (packed per row for every phase).
        let half = |wb: &mut WB, v: WB::Nat| -> [T; 2] {
            let l0 = wb.bits(v, 0, 16);
            let l1 = wb.bits(v, 16, 16);
            [wb.nat_to_field(l0), wb.nat_to_field(l1)]
        };
        cols.a = half(wb, a);
        cols.b = half(wb, b);
        cols.c = half(wb, c);
        cols.d = half(wb, d);
        cols.e = half(wb, e);
        cols.f = half(wb, f);
        cols.g = half(wb, g);
        cols.h = half(wb, h);

        // Compression gadgets: zero-masked inputs outside compression rows.
        let a_m = wb.select(is_comp, a, zero);
        let b_m = wb.select(is_comp, b, zero);
        let c_m = wb.select(is_comp, c, zero);
        let d_m = wb.select(is_comp, d, zero);
        let e_m = wb.select(is_comp, e, zero);
        let f_m = wb.select(is_comp, f, zero);
        let g_m = wb.select(is_comp, g, zero);
        let h_m = wb.select(is_comp, h, zero);
        let w_m = wb.select(is_comp, w_j, zero);
        let k_m = wb.select(is_comp, k_val, zero);
        wb.push_guard(is_comp);
        let e_rr_6 = FixedRotateRightOperation::<T>::witgen(wb, &mut cols.e_rr_6, e_m, 6);
        let e_rr_11 = FixedRotateRightOperation::<T>::witgen(wb, &mut cols.e_rr_11, e_m, 11);
        let e_rr_25 = FixedRotateRightOperation::<T>::witgen(wb, &mut cols.e_rr_25, e_m, 25);
        let s1_int =
            XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.s1_intermediate, e_rr_6, e_rr_11);
        let s1 = XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.s1, s1_int, e_rr_25);

        let e_and_f = AndU32Operation::<T>::witgen_and_u32(wb, &mut cols.e_and_f, e_m, f_m);
        let e_not = NotU32Operation::<T>::witgen(wb, &mut cols.e_not, e_m);
        // NotU32 of 0 is 0xFFFF_FFFF: mask its columns AND its downstream nat.
        cols.e_not.value[0] = wb.field_select(is_comp, cols.e_not.value[0], zero_f);
        cols.e_not.value[1] = wb.field_select(is_comp, cols.e_not.value[1], zero_f);
        let e_not_m = wb.select(is_comp, e_not, zero);
        let e_not_and_g =
            AndU32Operation::<T>::witgen_and_u32(wb, &mut cols.e_not_and_g, e_not_m, g_m);
        let ch = XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.ch, e_and_f, e_not_and_g);

        let temp1 = Add5Operation::<T>::witgen(wb, &mut cols.temp1, h_m, s1, ch, w_m, k_m);

        let a_rr_2 = FixedRotateRightOperation::<T>::witgen(wb, &mut cols.a_rr_2, a_m, 2);
        let a_rr_13 = FixedRotateRightOperation::<T>::witgen(wb, &mut cols.a_rr_13, a_m, 13);
        let a_rr_22 = FixedRotateRightOperation::<T>::witgen(wb, &mut cols.a_rr_22, a_m, 22);
        let s0_int =
            XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.s0_intermediate, a_rr_2, a_rr_13);
        let s0 = XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.s0, s0_int, a_rr_22);

        let a_and_b = AndU32Operation::<T>::witgen_and_u32(wb, &mut cols.a_and_b, a_m, b_m);
        let a_and_c = AndU32Operation::<T>::witgen_and_u32(wb, &mut cols.a_and_c, a_m, c_m);
        let b_and_c = AndU32Operation::<T>::witgen_and_u32(wb, &mut cols.b_and_c, b_m, c_m);
        let maj_int =
            XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.maj_intermediate, a_and_b, a_and_c);
        let maj = XorU32Operation::<T>::witgen_xor_u32(wb, &mut cols.maj, maj_int, b_and_c);

        let temp2 = AddU32Operation::<T>::witgen(wb, &mut cols.temp2, s0, maj);
        let _ = AddU32Operation::<T>::witgen(wb, &mut cols.d_add_temp1, d_m, temp1);
        let _ = AddU32Operation::<T>::witgen(wb, &mut cols.temp1_add_temp2, temp1, temp2);
        wb.pop_guard();

        // Finalize: h_out[j] = og_h[j] + final_h[j], operand column = final vars.
        let og_m = wb.select(is_fin, og_h_j, zero);
        let fin_m = wb.select(is_fin, final_h_j, zero);
        wb.push_guard(is_fin);
        let _ = AddU32Operation::<T>::witgen(wb, &mut cols.finalize_add, og_m, fin_m);
        wb.pop_guard();
        cols.finalized_operand = half(wb, fin_m);
        let _ = one;
    }
}
