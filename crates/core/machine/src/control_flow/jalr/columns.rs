use crate::adapter::{register::i_type::ITypeReader, state::CPUState};
use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::operations::AddOperation;

pub const NUM_JALR_COLS: usize = size_of::<JalrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct JalrColumns<T> {
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
}
