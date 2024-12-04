use crate::{
    operations::GlobalAccumulationOperation, operations::GlobalInteractionOperation,
    utils::pad_rows_fixed,
};
use core::fmt;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelBridge;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use sp1_core_executor::events::{ByteLookupEvent, ByteRecord};
use sp1_core_executor::{events::SyscallEvent, ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, SP1AirBuilder};
use sp1_stark::septic_digest::SepticDigest;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
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

    pub fn shard_kind(&self) -> SyscallShardKind {
        self.shard_kind
    }
}

pub const SYSCALL_INITIAL_DIGEST_POS_COPY: usize = 60;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T> {
    /// The shard number of the syscall.
    pub shard: T,

    /// The bottom 16 bits of clk of the syscall.
    pub clk_16: T,

    /// The top 8 bits of clk of the syscall.
    pub clk_8: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1.
    pub arg1: T,

    /// The arg2.
    pub arg2: T,

    pub is_real: T,

    /// The global interaction columns.
    pub global_interaction_cols: GlobalInteractionOperation<T>,

    /// The columns for accumulating the elliptic curve digests.
    pub global_accumulation_cols: GlobalAccumulationOperation<T, 1>,
}

impl<F: PrimeField32> MachineAir<F> for SyscallChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        format!("Syscall{}", self.shard_kind).to_string()
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let events = match self.shard_kind {
            SyscallShardKind::Core => &input.syscall_events,
            SyscallShardKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect::<Vec<_>>(),
        };
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_SYSCALL_COLS];
                    let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();
                    let clk_16 = (event.clk & 65535) as u16;
                    let clk_8 = (event.clk >> 16) as u8;
                    cols.global_interaction_cols.populate_syscall_range_check_witness(
                        event.shard,
                        clk_16,
                        clk_8,
                        event.syscall_code.syscall_id(),
                        true,
                        &mut blu,
                    );
                });
                blu
            })
            .collect::<Vec<_>>();
        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut global_cumulative_sum = SepticDigest::<F>::zero().0;

        let row_fn = |syscall_event: &SyscallEvent, is_receive: bool| {
            let mut row = [F::zero(); NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            debug_assert!(syscall_event.clk < (1 << 24));
            let clk_16 = (syscall_event.clk & 65535) as u16;
            let clk_8 = (syscall_event.clk >> 16) as u8;

            cols.shard = F::from_canonical_u32(syscall_event.shard);
            cols.clk_16 = F::from_canonical_u16(clk_16);
            cols.clk_8 = F::from_canonical_u8(clk_8);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_code.syscall_id());
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            cols.is_real = F::one();
            cols.global_interaction_cols.populate_syscall(
                syscall_event.shard,
                clk_16,
                clk_8,
                syscall_event.syscall_code.syscall_id(),
                syscall_event.arg1,
                syscall_event.arg2,
                is_receive,
                true,
            );
            row
        };

        let mut rows = match self.shard_kind {
            SyscallShardKind::Core => input
                .syscall_events
                .par_iter()
                .filter(|event| event.syscall_code.should_send() == 1)
                .map(|event| row_fn(event, false))
                .collect::<Vec<_>>(),
            SyscallShardKind::Precompile => input
                .precompile_events
                .all_events()
                .map(|(event, _)| event)
                .par_bridge()
                .map(|event| row_fn(event, true))
                .collect::<Vec<_>>(),
        };

        let num_events = rows.len();

        for i in 0..num_events {
            let cols: &mut SyscallCols<F> = rows[i].as_mut_slice().borrow_mut();
            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                [cols.global_interaction_cols],
                [cols.is_real],
            );
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_SYSCALL_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYSCALL_COLS);

        for i in num_events..trace.height() {
            let cols: &mut SyscallCols<F> =
                trace.values[i * NUM_SYSCALL_COLS..(i + 1) * NUM_SYSCALL_COLS].borrow_mut();
            cols.global_interaction_cols.populate_dummy();
            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                [cols.global_interaction_cols],
                [cols.is_real],
            );
        }

        trace
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
        let next = main.row_slice(1);
        let next: &SyscallCols<AB::Var> = (*next).borrow();

        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        match self.shard_kind {
            SyscallShardKind::Core => {
                builder.receive_syscall(
                    local.shard,
                    local.clk_16 + local.clk_8 * AB::Expr::from_canonical_u32(1 << 16),
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    InteractionScope::Local,
                );

                // Send the call to the global bus to/from the precompile chips.
                GlobalInteractionOperation::<AB::F>::eval_single_digest_syscall(
                    builder,
                    local.shard.into(),
                    local.clk_16.into(),
                    local.clk_8.into(),
                    local.syscall_id.into(),
                    local.arg1.into(),
                    local.arg2.into(),
                    local.global_interaction_cols,
                    false,
                    local.is_real,
                );
            }
            SyscallShardKind::Precompile => {
                builder.send_syscall(
                    local.shard,
                    local.clk_16 + local.clk_8 * AB::Expr::from_canonical_u32(1 << 16),
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    InteractionScope::Local,
                );

                GlobalInteractionOperation::<AB::F>::eval_single_digest_syscall(
                    builder,
                    local.shard.into(),
                    local.clk_16.into(),
                    local.clk_8.into(),
                    local.syscall_id.into(),
                    local.arg1.into(),
                    local.arg2.into(),
                    local.global_interaction_cols,
                    true,
                    local.is_real,
                );
            }
        }

        GlobalAccumulationOperation::<AB::F, 1>::eval_accumulation(
            builder,
            [local.global_interaction_cols],
            [local.is_real],
            [next.is_real],
            local.global_accumulation_cols,
            next.global_accumulation_cols,
        );
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
