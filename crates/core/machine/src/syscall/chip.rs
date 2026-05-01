use crate::{air::WordAirBuilder, utils::next_multiple_of_32, TrustMode};
use core::fmt;
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_core_executor::{
    events::{ByteRecord, GlobalInteractionEvent, SyscallEvent},
    ExecutionRecord, Program, SupervisorMode, TrapError, UserMode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    InteractionKind,
};
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};
use struct_reflection::{StructReflection, StructReflectionHelper};

/// The number of main trace columns for `SyscallChip` in supervisor mode.
pub const NUM_SYSCALL_COLS_SUPERVISOR: usize = size_of::<SyscallCols<u8, SupervisorMode>>();
/// The number of main trace columns for `SyscallChip` in user mode.
pub const NUM_SYSCALL_COLS_USER: usize = size_of::<SyscallCols<u8, UserMode>>();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallShardKind {
    Core,
    Precompile,
}

/// A chip that stores the syscall invocations.
pub struct SyscallChip<M: TrustMode> {
    shard_kind: SyscallShardKind,
    _phantom: PhantomData<M>,
}

impl<M: TrustMode> SyscallChip<M> {
    pub const fn new(shard_kind: SyscallShardKind) -> Self {
        Self { shard_kind, _phantom: std::marker::PhantomData }
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

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct SyscallCols<T: Copy, M: TrustMode> {
    /// The high bits of the clk of the syscall.
    pub clk_high: T,

    /// The low bits of clk of the syscall.
    pub clk_low: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1.
    pub arg1: [T; 3],

    /// The arg2.
    pub arg2: [T; 3],

    pub is_real: T,

    /// The trap code of the syscall.
    pub trap_code: M::TrapCodeCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for SyscallChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            match self.shard_kind {
                SyscallShardKind::Core => "SyscallCore",
                SyscallShardKind::Precompile => "SyscallPrecompile",
            }
        } else {
            match self.shard_kind {
                SyscallShardKind::Core => "SyscallCoreUser",
                SyscallShardKind::Precompile => "SyscallPrecompileUser",
            }
        }
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        let events = match self.shard_kind {
            SyscallShardKind::Core => &input
                .syscall_events
                .iter()
                .map(|(event, _)| event)
                .filter(|e| e.should_send)
                .copied()
                .collect::<Vec<_>>(),
            SyscallShardKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect::<Vec<_>>(),
        };

        let events = events
            .iter()
            .filter(|e| e.should_send)
            .map(|event| {
                let trap_code =
                    if let Some(TrapError::PagePermissionViolation(code)) = event.trap_error {
                        code as u8
                    } else {
                        0
                    };

                let mut blu = Vec::new();
                blu.add_u8_range_checks(&[event.syscall_id as u8, trap_code]);
                blu.add_u16_range_checks(&[(event.arg1 & 0xFFFF) as u16]);
                if !M::IS_TRUSTED {
                    blu.add_u16_range_checks(&[((event.arg1 >> 16) & 0xFFFF) as u16]);
                }

                let global_event = GlobalInteractionEvent {
                    message: [
                        (event.clk >> 24) as u32,
                        (event.clk & 0xFFFFFF) as u32,
                        event.syscall_id + (1 << 8) * (event.arg1 & 0xFFFF) as u32,
                        ((event.arg1 >> 16) & 0xFFFF) as u32 + ((trap_code as u32) << 16),
                        ((event.arg1 >> 32) & 0xFFFF) as u32,
                        (event.arg2 & 0xFFFF) as u32,
                        ((event.arg2 >> 16) & 0xFFFF) as u32,
                        ((event.arg2 >> 32) & 0xFFFF) as u32,
                    ],
                    is_receive: self.shard_kind == SyscallShardKind::Precompile,
                    kind: InteractionKind::Syscall as u8,
                };
                output.add_byte_lookup_events(blu);
                global_event
            })
            .collect_vec();
        output.global_interaction_events.extend(events);
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let events = match self.shard_kind {
            SyscallShardKind::Core => &input
                .syscall_events
                .iter()
                .map(|(event, _)| event)
                .filter(|e| e.should_send)
                .copied()
                .collect::<Vec<_>>(),
            SyscallShardKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect::<Vec<_>>(),
        };
        let nb_rows = events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        let row_fn = |syscall_event: &SyscallEvent, cols: &mut SyscallCols<F, M>| {
            cols.clk_high = F::from_canonical_u32((syscall_event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((syscall_event.clk & 0xFFFFFF) as u32);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_code.syscall_id());
            cols.arg1 = [
                F::from_canonical_u64((syscall_event.arg1 & 0xFFFF) as u64),
                F::from_canonical_u64(((syscall_event.arg1 >> 16) & 0xFFFF) as u64),
                F::from_canonical_u64(((syscall_event.arg1 >> 32) & 0xFFFF) as u64),
            ];
            cols.arg2 = [
                F::from_canonical_u64((syscall_event.arg2 & 0xFFFF) as u64),
                F::from_canonical_u64(((syscall_event.arg2 >> 16) & 0xFFFF) as u64),
                F::from_canonical_u64(((syscall_event.arg2 >> 32) & 0xFFFF) as u64),
            ];

            cols.is_real = F::one();
        };

        let padded_nb_rows = <SyscallChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let width = <Self as BaseAir<F>>::width(self);

        // Get event slice based on shard kind
        let events: Vec<&SyscallEvent> = match self.shard_kind {
            SyscallShardKind::Core => input
                .syscall_events
                .iter()
                .map(|(event, _)| event)
                .filter(|e| e.should_send)
                .collect(),
            SyscallShardKind::Precompile => {
                input.precompile_events.all_events().map(|(event, _)| event).collect()
            }
        };

        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        values.par_chunks_mut(width).enumerate().for_each(|(idx, row)| {
            if idx < events.len() {
                let cols: &mut SyscallCols<F, M> = row.borrow_mut();
                row_fn(events[idx], cols);
                if !M::IS_TRUSTED {
                    let cols: &mut SyscallCols<F, UserMode> = row.borrow_mut();
                    let trap_code = if let Some(TrapError::PagePermissionViolation(code)) =
                        events[idx].trap_error
                    {
                        code
                    } else {
                        0
                    };
                    cols.trap_code.trap_code = F::from_canonical_u64(trap_code);
                }
            }
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if shard.program.enable_untrusted_programs == M::IS_TRUSTED {
            return false;
        }
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.shard_kind {
                SyscallShardKind::Core => {
                    shard
                        .syscall_events
                        .iter()
                        .map(|(event, _)| event)
                        .filter(|e| e.should_send)
                        .take(1)
                        .count()
                        > 0
                }
                SyscallShardKind::Precompile => {
                    !shard.precompile_events.is_empty()
                        && !shard.contains_cpu()
                        && shard.global_memory_initialize_events.is_empty()
                        && shard.global_memory_finalize_events.is_empty()
                        && shard.global_page_prot_initialize_events.is_empty()
                        && shard.global_page_prot_finalize_events.is_empty()
                }
            }
        }
    }

    fn column_names(&self) -> Vec<String> {
        SyscallCols::<F, M>::struct_reflection().unwrap()
    }
}

impl<AB, M: TrustMode> Air<AB> for SyscallChip<M>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SyscallCols<AB::Var, M> = (*local).borrow();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        let mut trap_code = AB::Expr::zero();
        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &SyscallCols<AB::Var, UserMode> = (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            trap_code = local.trap_code.trap_code.into();
        }

        // Constrain that `local.is_real` is boolean.
        builder.assert_bool(local.is_real);

        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        // Constrain that the syscall id and trap code is 8 bits.
        builder.slice_range_check_u8(&[local.syscall_id.into(), trap_code.clone()], local.is_real);
        // Constrain that the arg1[0] is 16 bits.
        builder.slice_range_check_u16(&[local.arg1[0]], local.is_real);

        if !M::IS_TRUSTED {
            // Constrain that the arg1[1] is 16 bits.
            builder.slice_range_check_u16(&[local.arg1[1]], local.is_real);
        }

        #[cfg(not(feature = "mprotect"))]
        let arg4: AB::Expr = local.arg1[1].into().clone();
        #[cfg(feature = "mprotect")]
        let arg4: AB::Expr =
            local.arg1[1].into().clone() + trap_code.clone() * AB::F::from_canonical_u32(1 << 16);

        match self.shard_kind {
            SyscallShardKind::Core => {
                builder.receive_syscall(
                    local.clk_high,
                    local.clk_low,
                    local.syscall_id,
                    trap_code.clone(),
                    local.arg1.map(Into::into),
                    local.arg2.map(Into::into),
                    local.is_real,
                    InteractionScope::Local,
                );

                // Send the "send interaction" to the global table.
                builder.send(
                    AirInteraction::new(
                        vec![
                            local.clk_high.into(),
                            local.clk_low.into(),
                            local.syscall_id + local.arg1[0] * AB::F::from_canonical_u32(1 << 8),
                            arg4,
                            local.arg1[2].into(),
                            local.arg2[0].into(),
                            local.arg2[1].into(),
                            local.arg2[2].into(),
                            AB::Expr::one(),
                            AB::Expr::zero(),
                            AB::Expr::from_canonical_u8(InteractionKind::Syscall as u8),
                        ],
                        local.is_real.into(),
                        InteractionKind::Global,
                    ),
                    InteractionScope::Local,
                );
            }
            SyscallShardKind::Precompile => {
                builder.send_syscall(
                    local.clk_high,
                    local.clk_low,
                    local.syscall_id,
                    trap_code.clone(),
                    local.arg1.map(Into::into),
                    local.arg2.map(Into::into),
                    local.is_real,
                    InteractionScope::Local,
                );

                // Send the "receive interaction" to the global table.
                builder.send(
                    AirInteraction::new(
                        vec![
                            local.clk_high.into(),
                            local.clk_low.into(),
                            local.syscall_id + local.arg1[0] * AB::F::from_canonical_u32(1 << 8),
                            arg4,
                            local.arg1[2].into(),
                            local.arg2[0].into(),
                            local.arg2[1].into(),
                            local.arg2[2].into(),
                            AB::Expr::zero(),
                            AB::Expr::one(),
                            AB::Expr::from_canonical_u8(InteractionKind::Syscall as u8),
                        ],
                        local.is_real.into(),
                        InteractionKind::Global,
                    ),
                    InteractionScope::Local,
                );
            }
        }
    }
}

impl<F, M: TrustMode> BaseAir<F> for SyscallChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_SYSCALL_COLS_SUPERVISOR
        } else {
            NUM_SYSCALL_COLS_USER
        }
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
