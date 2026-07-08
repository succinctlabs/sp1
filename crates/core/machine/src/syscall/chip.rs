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

    /// The shard's SENDING syscall events for this shard kind — the rows that emit
    /// dependencies (byte lookups + one global interaction each).
    fn sending_events(&self, input: &ExecutionRecord) -> Vec<SyscallEvent> {
        match self.shard_kind {
            SyscallShardKind::Core => input
                .syscall_events
                .iter()
                .map(|(event, _)| *event)
                .filter(|e| e.should_send)
                .collect(),
            SyscallShardKind::Precompile => input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .filter(|e| e.should_send)
                .collect(),
        }
    }

    /// The global interaction of one sending syscall event: sent by the Core table,
    /// received by the Precompile table.
    fn global_event(&self, event: &SyscallEvent) -> GlobalInteractionEvent {
        let trap_code = syscall_trap_code(event);
        GlobalInteractionEvent {
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
        }
    }
}

/// The page-protection trap code of a syscall event (0 when it did not trap).
fn syscall_trap_code(event: &SyscallEvent) -> u8 {
    if let Some(TrapError::PagePermissionViolation(code)) = event.trap_error {
        code as u8
    } else {
        0
    }
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy, StructReflection)]
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

/// Witgen inputs for the syscall table: one `#[repr(C)]` row per event (see
/// `record_witgen_inputs` — field order IS the packed input layout).
///
/// `syscall_id` is the COLUMN value (`syscall_code.syscall_id()`);
/// `raw_syscall_id` is the DEPENDENCY value (`event.syscall_id`) — the two are
/// distinct event fields and must be packed separately for bit-fidelity.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallWitgenInput<T> {
    pub clk: T,
    pub syscall_id: T,
    pub raw_syscall_id: T,
    pub arg1: T,
    pub arg2: T,
    pub trap_code: T,
    /// Guard for the dependency lookups (Precompile-kind shards put non-sending
    /// events in the trace but skip them in `generate_dependencies`).
    pub should_send: T,
}

/// Number of witgen inputs per syscall row.
pub const NUM_SYSCALL_WITGEN_INPUTS: usize = size_of::<SyscallWitgenInput<u8>>();

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy, M: TrustMode> SyscallCols<T, M> {
    /// Backend-agnostic witgen for the syscall table (SUPERVISOR mode): clk split
    /// (24 low / 32 high), syscall id, and the arg1/arg2 u16 limbs, plus the
    /// dependency lookups — a u8 check on the RAW event syscall id + trap code and
    /// a u16 check on arg1's low limb — guarded by `should_send`. NOTE: the
    /// user-mode `trap_code` column and the extra `arg1[1]` u16 check are NOT
    /// emitted here (user mode is not device-ported).
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut SyscallCols<WB::Field, M>,
        input: &SyscallWitgenInput<WB::Nat>,
    ) {
        debug_assert!(M::IS_TRUSTED, "witgen ports the supervisor-mode syscall table only");
        let one = wb.const_nat(1);
        let clk_high = wb.bits(input.clk, 24, 32);
        cols.clk_high = wb.nat_to_field(clk_high);
        let clk_low = wb.bits(input.clk, 0, 24);
        cols.clk_low = wb.nat_to_field(clk_low);
        cols.syscall_id = wb.nat_to_field(input.syscall_id);
        let a1_limbs: [_; 3] = core::array::from_fn(|i| wb.bits(input.arg1, 16 * i as u32, 16));
        for (col, limb) in cols.arg1.iter_mut().zip(a1_limbs) {
            *col = wb.nat_to_field(limb);
        }
        for i in 0..3 {
            let limb = wb.bits(input.arg2, 16 * i as u32, 16);
            cols.arg2[i] = wb.nat_to_field(limb);
        }
        cols.is_real = wb.nat_to_field(one);

        // Dependency lookups: emitted only for sending events.
        wb.push_guard(input.should_send);
        wb.add_u8_range_check(input.raw_syscall_id, input.trap_code);
        wb.add_u16_range_check(a1_limbs[0]);
        wb.pop_guard();
    }
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
        // Byte-lookup half. Kept separate from the global half so a prover that
        // produces these lookups elsewhere (fused into the device tracegen kernel)
        // can run `generate_global_dependencies` alone.
        for event in self.sending_events(input) {
            let trap_code = syscall_trap_code(&event);
            let mut blu = Vec::new();
            blu.add_u8_range_checks(&[event.syscall_id as u8, trap_code]);
            blu.add_u16_range_checks(&[(event.arg1 & 0xFFFF) as u16]);
            if !M::IS_TRUSTED {
                blu.add_u16_range_checks(&[((event.arg1 >> 16) & 0xFFFF) as u16]);
            }
            output.add_byte_lookup_events(blu);
        }

        MachineAir::<F>::generate_global_dependencies(self, input, output);
    }

    fn generate_global_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        let events =
            self.sending_events(input).iter().map(|event| self.global_event(event)).collect_vec();
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

#[cfg(test)]
mod split_tests {
    use sp1_core_executor::{
        events::{MemoryReadRecord, MemoryRecordEnum, SyscallEvent},
        ExecutionRecord, RTypeRecord, SupervisorMode, SyscallCode,
    };
    use sp1_hypercube::air::MachineAir;
    use sp1_primitives::SP1Field;

    use super::SyscallChip;

    fn synth_events(n: u64) -> Vec<(SyscallEvent, RTypeRecord)> {
        let read = |seed: u64| {
            MemoryRecordEnum::Read(MemoryReadRecord {
                value: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                timestamp: seed * 2 + 10,
                prev_timestamp: seed * 2 + 1,
                prev_page_prot_record: None,
            })
        };
        let codes = [SyscallCode::HALT, SyscallCode::WRITE, SyscallCode::SHA_EXTEND];
        (0..n)
            .map(|i| {
                let code = codes[i as usize % codes.len()];
                let event = SyscallEvent {
                    pc: i * 4 + 4,
                    next_pc: i * 4 + 8,
                    clk: i * 8 + 8,
                    // Mix of sending and non-sending events, so the filter matters.
                    should_send: i % 3 != 0,
                    syscall_code: code,
                    syscall_id: code.syscall_id(),
                    arg1: i.wrapping_mul(0x1111_2222_3333) & 0xFFFF_FFFF_FFFF,
                    arg2: i.wrapping_mul(0x4444_5555_6666) & 0xFFFF_FFFF_FFFF,
                    exit_code: 0,
                    sig_return_pc_record: None,
                    trap_result: None,
                    trap_error: None,
                };
                let record = RTypeRecord {
                    op_a: (i % 31 + 1) as u8,
                    a: read(i * 3 + 1),
                    op_b: i % 31 + 1,
                    b: read(i * 3 + 2),
                    op_c: i % 31 + 1,
                    c: read(i * 3 + 3),
                    is_untrusted: false,
                };
                (event, record)
            })
            .collect()
    }

    /// `generate_global_dependencies` must be exactly the global subset of
    /// `generate_dependencies`: same global events in the same order and no byte
    /// lookups — the contract the device prover relies on when it fuses this chip's
    /// byte lookups into the tracegen kernel and keeps only the globals on host.
    #[test]
    fn global_dependencies_are_the_global_subset() {
        let shard = ExecutionRecord { syscall_events: synth_events(100), ..Default::default() };
        let chip = SyscallChip::<SupervisorMode>::core();

        let mut full = ExecutionRecord::default();
        MachineAir::<SP1Field>::generate_dependencies(&chip, &shard, &mut full);
        let mut globals_only = ExecutionRecord::default();
        MachineAir::<SP1Field>::generate_global_dependencies(&chip, &shard, &mut globals_only);

        assert_eq!(globals_only.global_interaction_events, full.global_interaction_events);
        assert!(!full.global_interaction_events.is_empty());
        assert!(globals_only.byte_lookups.is_empty());
        assert!(!full.byte_lookups.is_empty());
    }
}
