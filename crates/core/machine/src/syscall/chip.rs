use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{events::SyscallEvent, ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, SP1AirBuilder};

use crate::utils::pad_rows_fixed;

/// The number of main trace columns for `SyscallChip`.
pub const NUM_SYSCALL_COLS: usize = size_of::<SyscallCols<u8>>();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallShardKind {
    Core,
    Precompile,
}

/// A chip that stores the syscall invocations.
pub struct SyscallChip {
    shard_kind: SyscallShardKind,
}

impl SyscallChip {
    pub const fn new(shard_kind: SyscallShardKind) -> Self {
        Self { shard_kind }
    }

    pub const fn core() -> Self {
        Self::new(SyscallShardKind::Core)
    }

    pub const fn precompile() -> Self {
        Self::new(SyscallShardKind::Precompile)
    }
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T> {
    /// The shard number of the syscall.
    pub shard: T,

    /// The clk of the syscall.
    pub clk: T,

    pub nonce: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1.
    pub arg1: T,

    /// The arg2.
    pub arg2: T,

    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for SyscallChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        format!("Syscall{}", self.shard_kind).to_string()
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let row_fn = |syscall_event: &SyscallEvent| {
            let mut row = [F::zero(); NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(syscall_event.shard);
            cols.clk = F::from_canonical_u32(syscall_event.clk);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.nonce = F::from_canonical_u32(syscall_event.nonce);
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            cols.is_real = F::one();
            row
        };

        match self.shard_kind {
            SyscallShardKind::Core => {
                for event in input.syscall_events.iter() {
                    let row = row_fn(event);
                    rows.push(row);
                }
            }
            SyscallShardKind::Precompile => {
                for event in input.precompile_events.all_events().map(|(event, _)| event) {
                    let row = row_fn(event);
                    rows.push(row);
                }
            }
        };

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_SYSCALL_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYSCALL_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.shard_kind {
                SyscallShardKind::Core => !shard.syscall_events.is_empty(),
                SyscallShardKind::Precompile => {
                    !shard.precompile_events.is_empty()
                        && shard.cpu_events.is_empty()
                        && shard.global_memory_initialize_events.is_empty()
                        && shard.global_memory_finalize_events.is_empty()
                }
            }
        }
    }

    fn commit_scope(&self) -> InteractionScope {
        InteractionScope::Global
    }
}

impl<AB> Air<AB> for SyscallChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SyscallCols<AB::Var> = (*local).borrow();

        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        match self.shard_kind {
            SyscallShardKind::Core => {
                builder.receive_syscall(
                    local.shard,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    InteractionScope::Local,
                );

                // Send the call to the global bus to/from the precompile chips.
                builder.send_syscall(
                    local.shard,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    InteractionScope::Global,
                );
            }
            SyscallShardKind::Precompile => {
                builder.send_syscall(
                    local.shard,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    InteractionScope::Local,
                );

                // Send the call to the global bus to/from the precompile chips.
                builder.receive_syscall(
                    local.shard,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    InteractionScope::Global,
                );
            }
        }
    }
}

impl<F> BaseAir<F> for SyscallChip {
    fn width(&self) -> usize {
        NUM_SYSCALL_COLS
    }
}

impl fmt::Display for SyscallShardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallShardKind::Core => write!(f, "Core"),
            SyscallShardKind::Precompile => write!(f, "Precompile"),
        }
    }
}
