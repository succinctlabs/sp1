use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{register::i_type::ITypeReader, state::CPUState},
    operations::LtOperationSigned,
    SupervisorMode, TrustMode, UserMode,
};

/// The number of main trace columns for `BranchChip` in Supervisor mode.
pub const NUM_BRANCH_COLS_SUPERVISOR: usize = size_of::<BranchColumns<u8, SupervisorMode>>();
/// The number of main trace columns for `BranchChip` in User mode.
pub const NUM_BRANCH_COLS_USER: usize = size_of::<BranchColumns<u8, UserMode>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct BranchColumns<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// The next program counter.
    pub next_pc: [T; 3],

    /// Branch Instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_blt: T,
    pub is_bge: T,
    pub is_bltu: T,
    pub is_bgeu: T,

    /// The is_branching column is equal to:
    ///
    /// > is_beq & a_eq_b ||
    /// > is_bne & (a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & a_lt_b ||
    /// > (is_bge | is_bgeu) & (a_eq_b | a_gt_b)
    pub is_branching: T,

    /// The comparison between `a` and `b`.
    pub compare_operation: LtOperationSigned<T>,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T, M: TrustMode> BranchColumns<T, M> {
    /// Backend-agnostic witgen for the `Branch` chip (BEQ/BNE/BLT/BGE/BLTU/BGEU):
    /// the per-opcode flags, the signed/unsigned comparison (`LtOperationSigned`),
    /// the taken flag `is_branching`, and the `next_pc` limbs + range checks. The
    /// `a < b` result is host-computed (no lt op in the DSL) and passed as `a_lt_b`.
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut BranchColumns<WB::Field, M>,
        clk: WB::Nat,
        pc: WB::Nat,
        opcode: WB::Nat,
        event_a: WB::Nat,
        event_b: WB::Nat,
        next_pc: WB::Nat,
        a_lt_b: WB::Nat,
        op_a: WB::Nat,
        a_prev_value: WB::Nat,
        a_prev_ts: WB::Nat,
        a_cur_ts: WB::Nat,
        op_b: WB::Nat,
        b_prev_value: WB::Nat,
        b_prev_ts: WB::Nat,
        b_cur_ts: WB::Nat,
        op_c: WB::Nat,
    ) {
        use sp1_core_executor::Opcode;
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);

        let o_beq = wb.const_nat(Opcode::BEQ as u64);
        let o_bne = wb.const_nat(Opcode::BNE as u64);
        let o_blt = wb.const_nat(Opcode::BLT as u64);
        let o_bge = wb.const_nat(Opcode::BGE as u64);
        let o_bltu = wb.const_nat(Opcode::BLTU as u64);
        let o_bgeu = wb.const_nat(Opcode::BGEU as u64);
        let is_beq = wb.eq(opcode, o_beq);
        cols.is_beq = wb.nat_to_field(is_beq);
        let is_bne = wb.eq(opcode, o_bne);
        cols.is_bne = wb.nat_to_field(is_bne);
        let is_blt = wb.eq(opcode, o_blt);
        cols.is_blt = wb.nat_to_field(is_blt);
        let is_bge = wb.eq(opcode, o_bge);
        cols.is_bge = wb.nat_to_field(is_bge);
        let is_bltu = wb.eq(opcode, o_bltu);
        cols.is_bltu = wb.nat_to_field(is_bltu);
        let is_bgeu = wb.eq(opcode, o_bgeu);
        cols.is_bgeu = wb.nat_to_field(is_bgeu);

        // use_signed = BLT or BGE.
        let use_signed = wb.select(is_blt, one, is_bge);

        // The signed/unsigned comparison gadget (a = result, b/c = operands).
        LtOperationSigned::<WB::Field>::witgen(
            wb,
            &mut cols.compare_operation,
            a_lt_b,
            event_a,
            event_b,
            use_signed,
        );

        // is_branching = per opcode: BEQ→(a==b), BNE→(a!=b), BLT/BLTU→a<b,
        // BGE/BGEU→!(a<b).
        let a_eq_b = wb.eq(event_a, event_b);
        let not_eq = wb.eq(a_eq_b, zero);
        let not_lt = wb.eq(a_lt_b, zero);
        let is_lt_op = wb.select(is_blt, one, is_bltu);
        let t1 = wb.select(is_lt_op, a_lt_b, not_lt);
        let t2 = wb.select(is_bne, not_eq, t1);
        let branching = wb.select(is_beq, a_eq_b, t2);
        cols.is_branching = wb.nat_to_field(branching);

        // next_pc limbs (3) + range checks.
        for i in 0..3 {
            let l = wb.bits(next_pc, (i as u32) * 16, 16);
            cols.next_pc[i] = wb.nat_to_field(l);
        }
        let lq = wb.bits(next_pc, 2, 14);
        wb.add_bit_range_check(lq, 14);
        let l1 = wb.bits(next_pc, 16, 16);
        wb.add_u16_range_check(l1);
        let l2 = wb.bits(next_pc, 32, 16);
        wb.add_u16_range_check(l2);

        CPUState::<WB::Field>::witgen(wb, &mut cols.state, clk, pc);
        ITypeReader::<WB::Field>::witgen(
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
        );
    }
}
