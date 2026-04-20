use crate::{
    adapter::{register::j_type::JTypeReader, state::CPUState},
    operations::AddOperation,
    SupervisorMode, TrustMode, UserMode,
};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `JalChip` in Supervisor mode.
pub const NUM_JAL_COLS_SUPERVISOR: usize = size_of::<JalColumns<u8, SupervisorMode>>();
/// The number of main trace columns for `JalChip` in User mode.
pub const NUM_JAL_COLS_USER: usize = size_of::<JalColumns<u8, UserMode>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
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
