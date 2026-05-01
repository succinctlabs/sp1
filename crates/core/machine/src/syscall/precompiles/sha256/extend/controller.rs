use super::ShaExtendControlChip;
use crate::{
    air::SP1CoreAirBuilder,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};
use core::borrow::Borrow;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind, Word,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use std::{borrow::BorrowMut, iter::once, marker::PhantomData, mem::MaybeUninit};

impl<M: TrustMode> ShaExtendControlChip<M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

pub const fn num_sha_extend_control_cols_supervisor() -> usize {
    std::mem::size_of::<ShaExtendControlCols<u8, SupervisorMode>>()
}

pub const fn num_sha_extend_control_cols_user() -> usize {
    std::mem::size_of::<ShaExtendControlCols<u8, UserMode>>()
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendControlCols<T, M: TrustMode> {
    pub clk_high: T,
    pub clk_low: T,
    pub w_ptr: SyscallAddrOperation<T>,
    pub w_16th_addr: AddrAddOperation<T>,
    pub w_17th_addr: AddrAddOperation<T>,
    pub w_64th_addr: AddrAddOperation<T>,

    pub initial_page_prot_access: M::SliceProtCols<T>,
    pub extension_page_prot_access: M::SliceProtCols<T>,

    pub is_real: T,
}

impl<F, M: TrustMode> BaseAir<F> for ShaExtendControlChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            num_sha_extend_control_cols_supervisor()
        } else {
            num_sha_extend_control_cols_user()
        }
    }
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for ShaExtendControlChip<M> {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "ShaExtendControl"
        } else {
            "ShaExtendControlUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.get_precompile_events(SyscallCode::SHA_EXTEND).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let width = <ShaExtendControlChip<M> as BaseAir<F>>::width(self);
        let padded_nb_rows =
            <ShaExtendControlChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::SHA_EXTEND);
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

        let mut blu_events = Vec::new();

        values.chunks_mut(width).enumerate().for_each(|(idx, row)| {
            let event = &events[idx].1;
            let event =
                if let PrecompileEvent::ShaExtend(event) = event { event } else { unreachable!() };

            let cols: &mut ShaExtendControlCols<F, M> = row.borrow_mut();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            // This precompile accesses 64 words, which is 512 bytes.
            cols.w_ptr.populate(&mut blu_events, event.w_ptr, 512);
            // Address of 16th element of W, last read only element
            cols.w_16th_addr.populate(&mut blu_events, event.w_ptr, 15 * 8);
            // Address of 17th element of W, first written element
            cols.w_17th_addr.populate(&mut blu_events, event.w_ptr, 16 * 8);
            // Address of 64th element of W, last written element
            cols.w_64th_addr.populate(&mut blu_events, event.w_ptr, 63 * 8);
            cols.is_real = F::one();
            let mut is_not_trap = true;
            let mut trap_code = 0u8;

            // Constrain page prot access for initial 16 elements of W, read only
            if !M::IS_TRUSTED {
                let cols: &mut ShaExtendControlCols<F, UserMode> = row.borrow_mut();
                cols.initial_page_prot_access.populate(
                    &mut blu_events,
                    event.w_ptr,
                    event.w_ptr + 15 * 8,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.initial_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
                // Constrain page prot access for extension 48 elements of W, read and write
                cols.extension_page_prot_access.populate(
                    &mut blu_events,
                    event.w_ptr + 16 * 8,
                    event.w_ptr + 63 * 8,
                    event.clk + 1,
                    PROT_READ | PROT_WRITE,
                    &event.page_prot_records.extension_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
            }
        });

        output.add_byte_lookup_events(blu_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if M::IS_TRUSTED == shard.program.enable_untrusted_programs {
            return false;
        }

        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SHA_EXTEND).is_empty()
        }
    }
}

impl<AB, M: TrustMode> Air<AB> for ShaExtendControlChip<M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShaExtendControlCols<AB::Var, M> = (*local).borrow();

        // Check that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Check that `w_ptr` is within bounds.
        // SAFETY: `w_ptr` is with 3 u16 limbs, as it is received from the syscall.
        let w_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 512, local.w_ptr, local.is_real.into());

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word([
                AB::Expr::from_canonical_u32(15 * 8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.w_16th_addr,
            local.is_real.into(),
        );

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word([
                AB::Expr::from_canonical_u32(16 * 8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.w_17th_addr,
            local.is_real.into(),
        );

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word([
                AB::Expr::from_canonical_u32(63 * 8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.w_64th_addr,
            local.is_real.into(),
        );

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        let mut is_not_trap = local.is_real.into();
        let mut trap_code = AB::Expr::zero();

        // Evaluate the page prot accesses only for user mode.
        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &ShaExtendControlCols<AB::Var, UserMode> = (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &w_ptr.map(Into::into),
                &local.w_16th_addr.value.map(Into::into),
                PROT_READ,
                &local.initial_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::one(),
                &local.w_17th_addr.value.map(Into::into),
                &local.w_64th_addr.value.map(Into::into),
                PROT_READ | PROT_WRITE,
                &local.extension_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::SHA_EXTEND.syscall_id()),
            trap_code.clone(),
            w_ptr.map(Into::into),
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        // Send the initial state, with the starting index being 16.
        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into() + AB::Expr::one()))
            .chain(w_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(16)))
            .collect::<Vec<_>>();
        builder.send(
            AirInteraction::new(send_values, is_not_trap.clone(), InteractionKind::ShaExtend),
            InteractionScope::Local,
        );

        // Receive the final state, with the final index being 64.
        let receive_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into() + AB::Expr::one()))
            .chain(w_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(64)))
            .collect::<Vec<_>>();
        builder.receive(
            AirInteraction::new(receive_values, is_not_trap.clone(), InteractionKind::ShaExtend),
            InteractionScope::Local,
        );
    }
}
