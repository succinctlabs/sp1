use crate::adapter::{register::i_type::ITypeReader, state::CPUState};
use crate::{SupervisorMode, TrustMode, UserMode};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::operations::AddOperation;

/// The number of main trace columns for `JalrChip` in Supervisor mode.
pub const NUM_JALR_COLS_SUPERVISOR: usize = size_of::<JalrColumns<u8, SupervisorMode>>();
/// The number of main trace columns for `JalrChip` in User mode.
pub const NUM_JALR_COLS_USER: usize = size_of::<JalrColumns<u8, UserMode>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct JalrColumns<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// Whether or not the current row is a real row.
    pub is_real: T,

    /// Instance of `AddOperation` to handle addition logic in `JumpChip`.
    pub add_operation: AddOperation<T>,

    /// Computation of `pc + 4` if `op_a != X0`.
    pub op_a_operation: AddOperation<T>,

    /// The least significant bit of `op_b + op_c`.
    pub lsb: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T, M: TrustMode> JalrColumns<T, M> {
    /// Backend-agnostic witgen for the `Jalr` chip: `add_operation = b + imm` (the
    /// jump target, low bit cleared by the AIR), the `lsb` of `b + imm` + its
    /// `{Range, (b+imm)/4, 14}` check, `op_a_operation = pc + 4` (guarded+masked by
    /// op_a≠0), the `CPUState`, and the `ITypeReader`. `imm` is the op_c immediate.
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut JalrColumns<WB::Field, M>,
        clk: WB::Nat,
        pc: WB::Nat,
        op_a: WB::Nat,
        a_prev_value: WB::Nat,
        a_prev_ts: WB::Nat,
        a_cur_ts: WB::Nat,
        op_b: WB::Nat,
        b_prev_value: WB::Nat,
        b_prev_ts: WB::Nat,
        b_cur_ts: WB::Nat,
        op_c: WB::Nat,
        event_b: WB::Nat,
    ) {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        cols.is_real = wb.nat_to_field(one);

        let sum = wb.wrapping_add(event_b, op_c);
        let lq = wb.bits(sum, 2, 14);
        wb.add_bit_range_check(lq, 14);
        let lsb = wb.bits(sum, 0, 1);
        cols.lsb = wb.nat_to_field(lsb);
        AddOperation::<WB::Field>::witgen(wb, &mut cols.add_operation, event_b, op_c);

        let four = wb.const_nat(4);
        let is_op_a_zero = wb.eq(op_a, zero);
        let op_a_nz = wb.eq(is_op_a_zero, zero);
        let pc_m = wb.select(op_a_nz, pc, zero);
        let four_m = wb.select(op_a_nz, four, zero);
        wb.push_guard(op_a_nz);
        AddOperation::<WB::Field>::witgen(wb, &mut cols.op_a_operation, pc_m, four_m);
        wb.pop_guard();

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
