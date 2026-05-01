use super::{KeccakPermuteControlChip, STATE_NUM_WORDS};
use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessCols,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};
use core::borrow::Borrow;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind, Word,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use std::{borrow::BorrowMut, iter::once, marker::PhantomData, mem::MaybeUninit};

impl<M: TrustMode> KeccakPermuteControlChip<M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

pub const fn num_keccak_permute_control_cols_supervisor() -> usize {
    std::mem::size_of::<KeccakPermuteControlCols<u8, SupervisorMode>>()
}

pub const fn num_keccak_permute_control_cols_user() -> usize {
    std::mem::size_of::<KeccakPermuteControlCols<u8, UserMode>>()
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct KeccakPermuteControlCols<T, M: TrustMode> {
    pub clk_high: T,
    pub clk_low: T,
    pub state_addr: SyscallAddrOperation<T>,
    pub addrs: [AddrAddOperation<T>; 25],
    pub is_real: T,
    pub initial_memory_access: [MemoryAccessCols<T>; 25],
    pub final_memory_access: [MemoryAccessCols<T>; 25],
    pub final_value: [Word<T>; 25],

    /// Array Slice Page Prot Access.
    pub read_state_slice_page_prot_access: M::SliceProtCols<T>,
    pub write_state_slice_page_prot_access: M::SliceProtCols<T>,
}

impl<F, M: TrustMode> BaseAir<F> for KeccakPermuteControlChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            num_keccak_permute_control_cols_supervisor()
        } else {
            num_keccak_permute_control_cols_user()
        }
    }
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for KeccakPermuteControlChip<M> {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "KeccakPermuteControl"
        } else {
            "KeccakPermuteControlUser"
        }
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let width = <KeccakPermuteControlChip<M> as BaseAir<F>>::width(self);
        let mut blu_events = vec![];
        for (_, event) in input.get_precompile_events(SyscallCode::KECCAK_PERMUTE).iter() {
            let event = if let PrecompileEvent::KeccakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            let mut row = vec![F::zero(); width];
            let cols: &mut KeccakPermuteControlCols<F, M> = row.as_mut_slice().borrow_mut();
            cols.state_addr.populate(&mut blu_events, event.state_addr, 200);
            let mut is_not_trap = true;
            let mut trap_code = 0u8;

            if !M::IS_TRUSTED {
                let cols: &mut KeccakPermuteControlCols<F, UserMode> =
                    row.as_mut_slice().borrow_mut();
                cols.read_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.read_pre_state_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
                cols.write_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk + 1,
                    PROT_WRITE,
                    &event.page_prot_records.write_post_state_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
            }

            let cols: &mut KeccakPermuteControlCols<F, M> = row.as_mut_slice().borrow_mut();
            for i in 0..25 {
                cols.addrs[i].populate(&mut blu_events, event.state_addr, 8 * i as u64);
                if is_not_trap {
                    cols.initial_memory_access[i].populate(
                        MemoryRecordEnum::Read(event.state_read_records[i]),
                        &mut blu_events,
                    );
                    cols.final_memory_access[i].populate(
                        MemoryRecordEnum::Write(event.state_write_records[i]),
                        &mut blu_events,
                    );
                    cols.final_value[i] = Word::from(event.state_write_records[i].value);
                } else {
                    cols.initial_memory_access[i] = MemoryAccessCols::<F>::default();
                    cols.final_memory_access[i] = MemoryAccessCols::<F>::default();
                    cols.final_value[i] = Word::<F>::default();
                }
            }
        }
        output.add_byte_lookup_events(blu_events);
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE).len();
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

        let width = <KeccakPermuteControlChip<M> as BaseAir<F>>::width(self);
        let padded_nb_rows =
            <KeccakPermuteControlChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE);
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

        values.chunks_mut(width).enumerate().for_each(|(idx, row)| {
            let event = &events[idx].1;
            let event = if let PrecompileEvent::KeccakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            let cols: &mut KeccakPermuteControlCols<F, M> = row.borrow_mut();
            let mut blu_events = Vec::new();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.state_addr.populate(&mut blu_events, event.state_addr, 200);
            cols.is_real = F::one();

            let mut is_not_trap = true;
            let mut trap_code = 0u8;

            if !M::IS_TRUSTED {
                let cols: &mut KeccakPermuteControlCols<F, UserMode> = row.borrow_mut();
                cols.read_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.read_pre_state_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
                cols.write_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk + 1,
                    PROT_WRITE,
                    &event.page_prot_records.write_post_state_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
            }

            let cols: &mut KeccakPermuteControlCols<F, M> = row.borrow_mut();
            for i in 0..25 {
                cols.addrs[i].populate(&mut blu_events, event.state_addr, 8 * i as u64);
                if is_not_trap {
                    cols.initial_memory_access[i].populate(
                        MemoryRecordEnum::Read(event.state_read_records[i]),
                        &mut blu_events,
                    );
                    cols.final_memory_access[i].populate(
                        MemoryRecordEnum::Write(event.state_write_records[i]),
                        &mut blu_events,
                    );
                    cols.final_value[i] = Word::from(event.state_write_records[i].value);
                } else {
                    cols.initial_memory_access[i] = MemoryAccessCols::<F>::default();
                    cols.final_memory_access[i] = MemoryAccessCols::<F>::default();
                    cols.final_value[i] = Word::<F>::default();
                }
            }
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if M::IS_TRUSTED == shard.program.enable_untrusted_programs {
            return false;
        }

        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::KECCAK_PERMUTE).is_empty()
        }
    }
}

impl<AB, M: TrustMode> Air<AB> for KeccakPermuteControlChip<M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &KeccakPermuteControlCols<AB::Var, M> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let state_addr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            200,
            local.state_addr,
            local.is_real.into(),
        );

        let mut is_not_trap = local.is_real.into();
        let mut trap_code = AB::Expr::zero();

        // Evaluate the page prot accesses.
        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &KeccakPermuteControlCols<AB::Var, UserMode> = (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &local.state_addr.addr.map(Into::into),
                &local.addrs[STATE_NUM_WORDS - 1].value.map(Into::into),
                PROT_READ,
                &local.read_state_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::one(),
                &local.state_addr.addr.map(Into::into),
                &local.addrs[STATE_NUM_WORDS - 1].value.map(Into::into),
                PROT_WRITE,
                &local.write_state_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            trap_code.clone(),
            state_addr.map(Into::into),
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(state_addr.map(Into::into))
            .chain(once(AB::Expr::zero()))
            .chain(
                local
                    .initial_memory_access
                    .into_iter()
                    .flat_map(|access| access.prev_value.into_iter())
                    .map(Into::into),
            )
            .collect::<Vec<_>>();

        // Send the initial state.
        builder.send(
            AirInteraction::new(send_values, is_not_trap.clone(), InteractionKind::Keccak),
            InteractionScope::Local,
        );

        let receive_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(state_addr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(24)))
            .chain(local.final_value.into_iter().flat_map(|word| word.into_iter()).map(Into::into))
            .collect::<Vec<_>>();

        // Receive the final state.
        builder.receive(
            AirInteraction::new(receive_values, is_not_trap.clone(), InteractionKind::Keccak),
            InteractionScope::Local,
        );

        // addrs[i] = state_addr + 8 * i
        for i in 0..local.addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([
                    state_addr[0].into(),
                    state_addr[1].into(),
                    state_addr[2].into(),
                    AB::Expr::zero(),
                ]),
                Word::from(8 * i as u64),
                local.addrs[i],
                local.is_real.into(),
            );
        }

        // Evaluate the memory accesses.
        for i in 0..STATE_NUM_WORDS {
            builder.eval_memory_access_read(
                local.clk_high,
                local.clk_low,
                &local.addrs[i].value.map(Into::into),
                local.initial_memory_access[i],
                is_not_trap.clone(),
            );
            builder.eval_memory_access_write(
                local.clk_high,
                local.clk_low + AB::Expr::one(),
                &local.addrs[i].value.map(Into::into),
                local.final_memory_access[i],
                local.final_value[i],
                is_not_trap.clone(),
            );
        }

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );
    }
}
