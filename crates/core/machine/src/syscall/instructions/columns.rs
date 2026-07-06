use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::PV_DIGEST_NUM_WORDS, Word};
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{register::r_type::RTypeReader, state::CPUState},
    operations::{IsZeroOperation, SP1FieldWordRangeChecker, U16toU8Operation},
    SupervisorMode, TrustMode, UserMode,
};

pub const NUM_SYSCALL_INSTR_COLS_USER: usize = size_of::<SyscallInstrColumns<u8, UserMode>>();
pub const NUM_SYSCALL_INSTR_COLS_SUPERVISOR: usize =
    size_of::<SyscallInstrColumns<u8, SupervisorMode>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct SyscallInstrColumns<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: RTypeReader<T>,

    /// The next program counter.
    pub next_pc: [T; 3],

    /// Whether the current instruction is a halt instruction. This is verified by the
    /// is_halt_check operation.
    pub is_halt: T,

    /// The result of register op_a.
    pub op_a_value: Word<T>,

    /// Lower byte of two limbs of `b`.
    pub a_low_bytes: U16toU8Operation<T>,

    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current ecall is HINT_LEN.
    pub is_hint_len: IsZeroOperation<T>,

    /// Whether the current ecall is HALT.
    pub is_halt_check: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    /// Field to store the word index passed into the COMMIT ecall.  
    /// index_bitmap[word index] should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// The expected public values digest.
    pub expected_public_values_digest: [T; 4],

    /// The check if `op_b` is a valid SP1Field.
    pub op_b_range_check: SP1FieldWordRangeChecker<T>,

    /// The check if `op_c` is a valid SP1Field.
    pub op_c_range_check: SP1FieldWordRangeChecker<T>,

    /// Whether the current instruction is a real instruction.
    pub is_real: T,

    /// Columns for handling syscall instructions in user mode.
    pub user_mode_cols: M::SyscallInstrCols<T>,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T, M: TrustMode> SyscallInstrColumns<T, M> {
    /// Backend-agnostic witgen for the SUPERVISOR-mode `SyscallInstrs` chip: the
    /// dual of `event_to_row` + `state.populate` + `adapter.populate` in
    /// `trace.rs`. User-mode columns (`M::SyscallInstrCols`) are NOT populated —
    /// callers must only record this for `SupervisorMode` (where they are empty).
    ///
    /// The syscall id is the low byte of op_a's previous value; all five
    /// `SyscallCode` discriminators compare against constants < 256, so nat
    /// equality on the byte matches the host's field-element comparison.
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut SyscallInstrColumns<WB::Field, M>,
        clk: WB::Nat,
        pc: WB::Nat,
        op_a: WB::Nat,
        a_prev_value: WB::Nat,
        a_prev_ts: WB::Nat,
        a_cur_ts: WB::Nat,
        a_value: WB::Nat,
        op_b: WB::Nat,
        b_prev_value: WB::Nat,
        b_prev_ts: WB::Nat,
        b_cur_ts: WB::Nat,
        b_value: WB::Nat,
        op_c: WB::Nat,
        c_prev_value: WB::Nat,
        c_prev_ts: WB::Nat,
        c_cur_ts: WB::Nat,
        c_value: WB::Nat,
        arg1: WB::Nat,
        arg2: WB::Nat,
    ) {
        use sp1_core_executor::{SyscallCode, HALT_PC};

        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        cols.is_real = wb.nat_to_field(one);

        // op_a_value = Word::from(a.value()), each u16 limb range-checked
        // (`blu.add_u16_range_checks(&u64_to_u16_limbs(record.a.value()))`).
        for i in 0..4 {
            let limb = wb.bits(a_value, 16 * i as u32, 16);
            cols.op_a_value[i] = wb.nat_to_field(limb);
            wb.add_u16_range_check(limb);
        }

        // Low byte of each u16 limb of op_a's PREVIOUS value (safe variant emits
        // one u8 range-check pair per limb).
        U16toU8Operation::<WB::Field>::witgen_safe(wb, &mut cols.a_low_bytes, a_prev_value);

        // The syscall id is the low byte of op_a's previous value.
        let sid = wb.bits(a_prev_value, 0, 8);

        // is_halt + next_pc: [HALT_PC, 0, 0] on halt, else pc limbs with limb 0
        // bumped by 4 (no carry propagation — mirrors the host exactly).
        let halt_code = wb.const_nat(SyscallCode::HALT.syscall_id() as u64);
        let is_halt = wb.eq(sid, halt_code);
        cols.is_halt = wb.nat_to_field(is_halt);
        let halt_pc = wb.const_nat(HALT_PC);
        let four = wb.const_nat(4);
        let pc0 = wb.bits(pc, 0, 16);
        let pc0p4 = wb.wrapping_add(pc0, four);
        let np0 = wb.select(is_halt, halt_pc, pc0p4);
        cols.next_pc[0] = wb.nat_to_field(np0);
        let pc1 = wb.bits(pc, 16, 16);
        let np1 = wb.select(is_halt, zero, pc1);
        cols.next_pc[1] = wb.nat_to_field(np1);
        let pc2 = wb.bits(pc, 32, 16);
        let np2 = wb.select(is_halt, zero, pc2);
        cols.next_pc[2] = wb.nat_to_field(np2);

        // The five syscall-id discriminators (IsZero on the field difference
        // `syscall_id - code`).
        let euc_code = wb.const_nat(SyscallCode::ENTER_UNCONSTRAINED.syscall_id() as u64);
        IsZeroOperation::<WB::Field>::witgen_nat_diff(
            wb,
            &mut cols.is_enter_unconstrained,
            sid,
            euc_code,
        );
        let hint_code = wb.const_nat(SyscallCode::HINT_LEN.syscall_id() as u64);
        IsZeroOperation::<WB::Field>::witgen_nat_diff(wb, &mut cols.is_hint_len, sid, hint_code);
        IsZeroOperation::<WB::Field>::witgen_nat_diff(wb, &mut cols.is_halt_check, sid, halt_code);
        let commit_code = wb.const_nat(SyscallCode::COMMIT.syscall_id() as u64);
        let is_commit = IsZeroOperation::<WB::Field>::witgen_nat_diff(
            wb,
            &mut cols.is_commit,
            sid,
            commit_code,
        );
        let cdp_code = wb.const_nat(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id() as u64);
        let is_cdp = IsZeroOperation::<WB::Field>::witgen_nat_diff(
            wb,
            &mut cols.is_commit_deferred_proofs,
            sid,
            cdp_code,
        );

        // index_bitmap: one-hot at op_b's value for COMMIT / COMMIT_DEFERRED_PROOFS
        // (the two codes are distinct, so the flag sum is 0/1).
        let commit_or_cdp = wb.wrapping_add(is_commit, is_cdp);
        for (k, slot) in cols.index_bitmap.iter_mut().enumerate() {
            let k_n = wb.const_nat(k as u64);
            let eq_k = wb.eq(b_value, k_n);
            let bit = wb.mul(commit_or_cdp, eq_k);
            *slot = wb.nat_to_field(bit);
        }

        // expected_public_values_digest: the 4 le bytes of (op_c's value as u32) on
        // COMMIT (columns masked; the two u8 range-check pairs guarded).
        let mut dig = [zero; 4];
        for (i, byte_slot) in dig.iter_mut().enumerate() {
            let byte = wb.bits(c_value, 8 * i as u32, 8);
            let masked = wb.mul(is_commit, byte);
            cols.expected_public_values_digest[i] = wb.nat_to_field(masked);
            *byte_slot = byte;
        }
        wb.push_guard(is_commit);
        wb.add_u8_range_check(dig[0], dig[1]);
        wb.add_u8_range_check(dig[2], dig[3]);
        wb.pop_guard();

        // SP1Field-word range checks: op_b (arg1) on HALT, op_c (arg2) on
        // COMMIT_DEFERRED_PROOFS; default columns / no lookups otherwise.
        SP1FieldWordRangeChecker::<WB::Field>::witgen(
            wb,
            &mut cols.op_b_range_check,
            arg1,
            is_halt,
        );
        SP1FieldWordRangeChecker::<WB::Field>::witgen(wb, &mut cols.op_c_range_check, arg2, is_cdp);

        CPUState::<WB::Field>::witgen(wb, &mut cols.state, clk, pc);
        RTypeReader::<WB::Field>::witgen(
            wb,
            &mut cols.adapter,
            op_a,
            a_prev_value,
            a_prev_ts,
            a_cur_ts,
            op_b,
            b_prev_value,
            b_prev_ts,
            b_cur_ts,
            op_c,
            c_prev_value,
            c_prev_ts,
            c_cur_ts,
        );
    }
}
