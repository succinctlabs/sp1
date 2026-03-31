use crate::{
    adapter::{register::j_type::JTypeReader, state::CPUState},
    operations::AddOperation,
};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

pub const NUM_JAL_COLS: usize = size_of::<JalColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct JalColumns<T> {
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
}
