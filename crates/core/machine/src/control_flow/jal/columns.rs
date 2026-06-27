use crate::{
    adapter::{register::j_type::JTypeReader, state::CPUState},
    operations::AddOperation,
    SupervisorMode, TrustMode, UserMode,
};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

/// The number of main trace columns for `JalChip` in Supervisor mode.
pub const NUM_JAL_COLS_SUPERVISOR: usize = size_of::<JalColumns<u8, SupervisorMode>>();
/// The number of main trace columns for `JalChip` in User mode.
pub const NUM_JAL_COLS_USER: usize = size_of::<JalColumns<u8, UserMode>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct JalColumns<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: JTypeReader<T>,

    /// AddOperation to get `imm_b + imm_c` as the next program counter.
    pub add_operation: AddOperation<T>,

    /// AddOperation to get `op_a` as `pc + 4` if `op_a_0` is false.
    pub op_a_operation: AddOperation<T>,

    /// Whether or not the current row is a real row.
    pub is_real: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T, M: TrustMode> JalColumns<T, M> {
    /// Backend-agnostic witgen for the `Jal` chip: `add_operation = pc + b` (the
    /// jump target) and `op_a_operation = pc + 4` (the return address, guarded+masked
    /// by op_a≠0 — a write to x0 zeroes it), plus the `CPUState` and `JTypeReader`.
    #[allow(clippy::too_many_arguments)]
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut JalColumns<WB::Field, M>,
        clk: WB::Nat,
        pc: WB::Nat,
        op_a: WB::Nat,
        a_prev_value: WB::Nat,
        a_prev_ts: WB::Nat,
        a_cur_ts: WB::Nat,
        op_b: WB::Nat,
        op_c: WB::Nat,
        event_b: WB::Nat,
    ) {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        cols.is_real = wb.nat_to_field(one);
        AddOperation::<WB::Field>::witgen(wb, &mut cols.add_operation, pc, event_b);

        let four = wb.const_nat(4);
        let is_op_a_zero = wb.eq(op_a, zero);
        let op_a_nz = wb.eq(is_op_a_zero, zero);
        let pc_m = wb.select(op_a_nz, pc, zero);
        let four_m = wb.select(op_a_nz, four, zero);
        wb.push_guard(op_a_nz);
        AddOperation::<WB::Field>::witgen(wb, &mut cols.op_a_operation, pc_m, four_m);
        wb.pop_guard();

        CPUState::<WB::Field>::witgen(wb, &mut cols.state, clk, pc);
        JTypeReader::<WB::Field>::witgen(
            wb,
            &mut cols.adapter,
            op_a,
            a_prev_value,
            a_prev_ts,
            a_cur_ts,
            op_b,
            op_c,
        );
    }
}
