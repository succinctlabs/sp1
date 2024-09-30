use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, SP1AirBuilder};

use crate::utils::pad_to_power_of_two;

/// The number of main trace columns for `SyscallChip`.
pub const NUM_SYSCALL_COLS: usize = size_of::<SyscallCols<u8>>();

/// A chip that stores the syscall invocations.
#[derive(Default)]
pub struct SyscallChip;

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
        "Syscall".to_string()
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

        for syscall_event in input.syscall_events.iter() {
            let mut row = [F::zero(); NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(syscall_event.shard);
            cols.clk = F::from_canonical_u32(syscall_event.clk);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.nonce = F::from_canonical_u32(
                input.nonce_lookup.get(&syscall_event.lookup_id).copied().unwrap_or_default(),
            );
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            cols.is_real = F::one();

            rows.push(row);
        }
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYSCALL_COLS);

        pad_to_power_of_two::<NUM_SYSCALL_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.syscall_events.is_empty()
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

        // Receive the calls from the local bus from the CPU.
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

        // Send the call to the global bus to the precompile chips.
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
}

impl<F> BaseAir<F> for SyscallChip {
    fn width(&self) -> usize {
        NUM_SYSCALL_COLS
    }
}
