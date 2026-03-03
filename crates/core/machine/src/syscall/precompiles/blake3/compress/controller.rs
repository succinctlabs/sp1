use core::borrow::Borrow;
use std::{borrow::BorrowMut, iter::once, mem::MaybeUninit};

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

use super::{Blake3CompressControlChip, ROWS_PER_INVOCATION};
use crate::{
    air::SP1CoreAirBuilder,
    operations::{AddrAddOperation, SyscallAddrOperation},
    utils::{next_multiple_of_32, u32_to_half_word},
};

pub const NUM_BLAKE3_COMPRESS_CONTROL_COLS: usize =
    size_of::<Blake3CompressControlCols<u8>>();

/// Last element offset (in units of 8-byte words) for a 16-word array.
const OFFSET_LAST_ELEM: u64 = 15;

/// Total byte span of a 16-word array in the 64-bit SP1 memory model.
const ARRAY_BYTE_LEN: u64 = 16 * 8; // = 128

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3CompressControlCols<T> {
    pub clk_high: T,
    pub clk_low: T,
    /// Validated state pointer (16 × 8 bytes = 128 bytes).
    pub state_ptr: SyscallAddrOperation<T>,
    /// Validated message pointer (16 × 8 bytes = 128 bytes).
    pub msg_ptr: SyscallAddrOperation<T>,
    /// Address of the last state element (for slice validation).
    pub state_slice_end: AddrAddOperation<T>,
    /// Address of the last msg element (for slice validation).
    pub msg_slice_end: AddrAddOperation<T>,
    pub is_real: T,
    /// Initial state (state_in): 16 words × 2 u16 limbs.
    pub initial_state: [[T; 2]; 16],
    /// Message words: 16 words × 2 u16 limbs.
    pub msg: [[T; 2]; 16],
    /// Final state (state_out): 16 words × 2 u16 limbs.
    pub final_state: [[T; 2]; 16],
}

impl Blake3CompressControlChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for Blake3CompressControlChip {
    fn width(&self) -> usize {
        NUM_BLAKE3_COMPRESS_CONTROL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for Blake3CompressControlChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "Blake3CompressControl"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            input.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER).len();
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
        let padded_nb_rows =
            <Blake3CompressControlChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER);
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_BLAKE3_COMPRESS_CONTROL_COLS;
            let padding_size =
                (padded_nb_rows - num_event_rows) * NUM_BLAKE3_COMPRESS_CONTROL_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                num_event_rows * NUM_BLAKE3_COMPRESS_CONTROL_COLS,
            )
        };

        let mut blu_events = Vec::new();

        values
            .chunks_mut(NUM_BLAKE3_COMPRESS_CONTROL_COLS)
            .enumerate()
            .for_each(|(idx, row)| {
                let event = &events[idx].1;
                let event = if let PrecompileEvent::Blake3CompressInner(event) = event {
                    event
                } else {
                    unreachable!()
                };
                let cols: &mut Blake3CompressControlCols<F> = row.borrow_mut();
                cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
                // state_ptr covers 16 × 8 = 128 bytes.
                cols.state_ptr.populate(&mut blu_events, event.state_ptr, ARRAY_BYTE_LEN);
                cols.msg_ptr.populate(&mut blu_events, event.msg_ptr, ARRAY_BYTE_LEN);
                cols.state_slice_end.populate(
                    &mut blu_events,
                    event.state_ptr,
                    OFFSET_LAST_ELEM * 8,
                );
                cols.msg_slice_end.populate(
                    &mut blu_events,
                    event.msg_ptr,
                    OFFSET_LAST_ELEM * 8,
                );
                cols.is_real = F::one();
                for i in 0..16 {
                    cols.initial_state[i] = u32_to_half_word(event.state_in[i]);
                    cols.msg[i] = u32_to_half_word(event.msg[i]);
                    cols.final_state[i] = u32_to_half_word(event.state_out[i]);
                }
            });

        output.add_byte_lookup_events(blu_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER).is_empty()
        }
    }
}

impl<AB> Air<AB> for Blake3CompressControlChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Blake3CompressControlCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // Validate and extract the two pointers.
        let state_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            ARRAY_BYTE_LEN as u32,
            local.state_ptr,
            local.is_real.into(),
        );
        let msg_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            ARRAY_BYTE_LEN as u32,
            local.msg_ptr,
            local.is_real.into(),
        );

        // Constrain the slice-end address computations.
        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([
                state_ptr[0].into(),
                state_ptr[1].into(),
                state_ptr[2].into(),
                AB::Expr::zero(),
            ]),
            Word::from(OFFSET_LAST_ELEM * 8),
            local.state_slice_end,
            local.is_real.into(),
        );
        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([
                msg_ptr[0].into(),
                msg_ptr[1].into(),
                msg_ptr[2].into(),
                AB::Expr::zero(),
            ]),
            Word::from(OFFSET_LAST_ELEM * 8),
            local.msg_slice_end,
            local.is_real.into(),
        );

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::BLAKE3_COMPRESS_INNER.syscall_id()),
            state_ptr.map(Into::into),
            msg_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        // Send the initial (state, msg) at index = 0.
        let send_values: Vec<AB::Expr> = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(state_ptr.map(Into::into))
            .chain(msg_ptr.map(Into::into))
            .chain(once(AB::Expr::zero())) // index = 0
            .chain(
                local.initial_state.into_iter().flat_map(|w| w.into_iter()).map(Into::into),
            )
            .chain(local.msg.into_iter().flat_map(|w| w.into_iter()).map(Into::into))
            .collect();
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::Blake3Compress),
            InteractionScope::Local,
        );

        // Receive the final (state, msg) at index = ROWS_PER_INVOCATION.
        let receive_values: Vec<AB::Expr> = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(state_ptr.map(Into::into))
            .chain(msg_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(ROWS_PER_INVOCATION as u32)))
            .chain(
                local.final_state.into_iter().flat_map(|w| w.into_iter()).map(Into::into),
            )
            .chain(local.msg.into_iter().flat_map(|w| w.into_iter()).map(Into::into))
            .collect();
        builder.receive(
            AirInteraction::new(
                receive_values,
                local.is_real.into(),
                InteractionKind::Blake3Compress,
            ),
            InteractionScope::Local,
        );
    }
}
