use sp1_derive::AlignedBorrow;
use std::mem::size_of;

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
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
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
