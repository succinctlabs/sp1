use crate::memory::MemoryAccessCols;
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
    air::{InteractionScope, MachineAir},
    Word,
};
use std::{borrow::BorrowMut, mem::MaybeUninit};

use crate::{
    air::SP1CoreAirBuilder,
    operations::{AddrAddOperation, SyscallAddrOperation},
    utils::next_multiple_of_32,
};

/// The number of columns in the SigReturnCols.
const NUM_COLS: usize = size_of::<SigReturnCols<u8>>();

#[derive(Default)]
pub struct SigReturnChip;

impl SigReturnChip {
    pub const fn new() -> Self {
        Self
    }
}

/// A set of columns for the SigReturn operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct SigReturnCols<T> {
    /// Clock cycle of the syscall (split into high and low parts)
    pub clk_high: T,
    pub clk_low: T,

    pub ptr: SyscallAddrOperation<T>,
    pub addrs: [AddrAddOperation<T>; 31],
    pub memory_read_records: [MemoryAccessCols<T>; 31],
    pub register_write_records: [MemoryAccessCols<T>; 31], // x1 ~ x31

    pub is_real: T,
}

impl<F> BaseAir<F> for SigReturnChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for SigReturnChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "SigReturn"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::SIG_RETURN).len();
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
        let padded_nb_rows = <SigReturnChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut blu_events = Vec::new();

        let sig_return_events = input.get_precompile_events(SyscallCode::SIG_RETURN);
        let num_event_rows = sig_return_events.len();
        if input.public_values.is_untrusted_programs_enabled == 0 {
            assert!(
                sig_return_events.is_empty(),
                "Page protect is disabled, but sig_return events are present"
            );
        }

        unsafe {
            let padding_start = num_event_rows * NUM_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_COLS) };

        values.chunks_mut(NUM_COLS).enumerate().for_each(|(idx, row)| {
            let event = &sig_return_events[idx].1;
            let event =
                if let PrecompileEvent::SigReturn(event) = event { event } else { unreachable!() };

            let cols: &mut SigReturnCols<F> = row.borrow_mut();

            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

            cols.ptr.populate(&mut blu_events, event.ptr, 8 * 32);

            for i in 0..31 {
                cols.addrs[i].populate(&mut blu_events, event.ptr, (8 + 8 * i) as u64);
                cols.memory_read_records[i].populate(
                    MemoryRecordEnum::Read(event.memory_read_records[i]),
                    &mut blu_events,
                );
                cols.register_write_records[i].populate(
                    MemoryRecordEnum::Write(event.register_write_records[i]),
                    &mut blu_events,
                );
            }

            cols.is_real = F::one();
        });

        // Add byte lookup events to output
        output.add_byte_lookup_events(blu_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SIG_RETURN).is_empty()
        }
    }
}

impl<AB> Air<AB> for SigReturnChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SigReturnCols<AB::Var> = (*local).borrow();

        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(local.is_real);

        builder.assert_bool(local.is_real);
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::one(),
        );

        let ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32 * 8, local.ptr, local.is_real.into());

        for i in 0..31 {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), AB::Expr::zero()]),
                Word::from((8 * i + 8) as u64),
                local.addrs[i],
                local.is_real.into(),
            );
            builder.eval_memory_access_read(
                local.clk_high,
                local.clk_low,
                &local.addrs[i].value.map(Into::into),
                local.memory_read_records[i],
                local.is_real,
            );
            builder.eval_memory_access_write(
                local.clk_high,
                local.clk_low + AB::Expr::from_canonical_u8(5),
                &[AB::Expr::from_canonical_usize(1 + i), AB::Expr::zero(), AB::Expr::zero()],
                local.register_write_records[i],
                local.memory_read_records[i].prev_value,
                local.is_real,
            );
        }

        // Receive the syscall interaction
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::SIG_RETURN.syscall_id()),
            AB::Expr::zero(),
            ptr.map(Into::into),
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );
    }
}
