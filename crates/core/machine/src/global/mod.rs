use std::{
    borrow::Borrow,
    mem::{transmute, MaybeUninit},
};

use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelBridge,
    ParallelIterator,
};
use rayon_scan::ScanParallelIterator;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, GlobalInteractionEvent},
    ExecutionRecord, Program,
};
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    septic_extension::SepticExtension,
    InteractionKind,
};
use std::borrow::BorrowMut;

use crate::{
    operations::{GlobalAccumulationOperation, GlobalInteractionOperation},
    utils::{indices_arr, next_multiple_of_32},
};
use sp1_derive::AlignedBorrow;

const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();

/// Creates the column map for the CPU.
const fn make_col_map() -> GlobalCols<usize> {
    let indices_arr = indices_arr::<NUM_GLOBAL_COLS>();
    unsafe { transmute::<[usize; NUM_GLOBAL_COLS], GlobalCols<usize>>(indices_arr) }
}

const GLOBAL_COL_MAP: GlobalCols<usize> = make_col_map();

pub const GLOBAL_INITIAL_DIGEST_POS: usize = GLOBAL_COL_MAP.accumulation.initial_digest[0].0[0];

const GLOBAL_OFFSET_POS: usize = GLOBAL_COL_MAP.interaction.offset;

pub const GLOBAL_INITIAL_DIGEST_POS_COPY: usize = 213;

pub const GLOBAL_OFFSET_POS_COPY: usize = 204;

#[repr(C)]
pub struct Ghost {
    pub v: [usize; GLOBAL_INITIAL_DIGEST_POS_COPY],
}

#[derive(Default)]
pub struct GlobalChip;

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GlobalCols<T: Copy> {
    pub message: [T; 8],
    pub kind: T,
    pub message_0_16bit_limb: T,
    pub message_0_8bit_limb: T,
    pub interaction: GlobalInteractionOperation<T>,
    pub is_real: T,
    pub is_receive: T,
    pub is_send: T,
    pub index: T,
    pub accumulation: GlobalAccumulationOperation<T>,
}

impl<F: PrimeField32> MachineAir<F> for GlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        debug_assert_eq!(GLOBAL_INITIAL_DIGEST_POS_COPY, GLOBAL_INITIAL_DIGEST_POS);
        debug_assert_eq!(GLOBAL_OFFSET_POS_COPY, GLOBAL_OFFSET_POS);
        "Global"
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = &input.global_interaction_events;

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .par_bridge()
            .map(|events| {
                let mut blu: Vec<ByteLookupEvent> = Vec::new();
                let mut row = [F::zero(); NUM_GLOBAL_COLS];
                let cols: &mut GlobalCols<F> = row.as_mut_slice().borrow_mut();
                events.iter().for_each(|event| {
                    let message0_16bit_limb = (event.message[0] & 0xffff) as u16;
                    let message0_8bit_limb = ((event.message[0] >> 16) & 0xff) as u8;
                    blu.add_u16_range_check(message0_16bit_limb);
                    blu.add_u16_range_check(event.message[7] as u16);
                    blu.add_u8_range_check(message0_8bit_limb, 0);
                    blu.add_bit_range_check(event.kind as u16, 6);
                    if !input.global_dependencies_opt {
                        cols.interaction.populate(
                            &mut blu,
                            event.message,
                            event.is_receive,
                            true,
                            event.kind,
                        );
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
        output.public_values.global_count = events.len() as u32;
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.global_interaction_events;
        let nb_rows = events.len();
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
        let events = &input.global_interaction_events;

        let nb_rows = events.len();

        let padded_nb_rows = <GlobalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * NUM_GLOBAL_COLS)
        };
        let mut chunks = values[..nb_rows * NUM_GLOBAL_COLS]
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks = Vec::with_capacity(chunk_size * NUM_GLOBAL_COLS + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                let mut blu = Vec::new();
                rows.chunks_mut(NUM_GLOBAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut GlobalCols<F> = row.borrow_mut();
                    let event: &GlobalInteractionEvent = &events[idx];
                    cols.message = event.message.map(F::from_canonical_u32);
                    cols.kind = F::from_canonical_u8(event.kind);
                    cols.index = F::from_canonical_u32(idx as u32);
                    cols.interaction.populate(
                        &mut blu,
                        event.message,
                        event.is_receive,
                        true,
                        event.kind,
                    );
                    cols.is_real = F::one();
                    if event.is_receive {
                        cols.is_receive = F::one();
                        cols.is_send = F::zero();
                    } else {
                        cols.is_receive = F::zero();
                        cols.is_send = F::one();
                    }
                    cols.message_0_16bit_limb =
                        F::from_canonical_u16((event.message[0] & 0xffff) as u16);
                    cols.message_0_8bit_limb =
                        F::from_canonical_u8(((event.message[0] >> 16) & 0xff) as u8);
                    point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                        x: SepticExtension(cols.interaction.x_coordinate.0),
                        y: SepticExtension(cols.interaction.y_coordinate.0),
                    }));
                });
                point_chunks
            })
            .collect::<Vec<_>>();

        let points = point_chunks.into_iter().flatten().collect::<Vec<_>>();
        let cumulative_sum = points
            .into_par_iter()
            .with_min_len(1 << 15)
            .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = match cumulative_sum.last() {
            Some(digest) => digest.point(),
            None => SepticDigest::<F>::zero().0,
        };

        let mut global_sum = input.global_cumulative_sum.lock().unwrap();
        *global_sum = SepticDigest(SepticCurve::convert(final_digest, |x| F::as_canonical_u32(&x)));

        output.global_interaction_event_count = nb_rows as u32;

        let start_digest = SepticDigest::<F>::zero().0;
        let dummy = SepticCurve::<F>::dummy();
        let start_digest_plus_dummy = start_digest.add_incomplete(dummy);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values.chunks_mut(chunk_size * NUM_GLOBAL_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_GLOBAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    if idx >= nb_rows {
                        unsafe {
                            core::ptr::write_bytes(row.as_mut_ptr(), 0, NUM_GLOBAL_COLS);
                        }
                    }
                    let cols: &mut GlobalCols<F> = row.borrow_mut();
                    if idx < nb_rows {
                        cols.accumulation.populate_real(&cumulative_sum[idx..idx + 2]);
                    } else {
                        cols.interaction.populate_dummy();
                        cols.accumulation.populate_dummy(start_digest, start_digest_plus_dummy);
                    }
                });
            },
        );
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for GlobalChip {
    fn width(&self) -> usize {
        NUM_GLOBAL_COLS
    }
}

impl<AB> Air<AB> for GlobalChip
where
    AB: SP1AirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &GlobalCols<AB::Var> = (*local).borrow();

        // Constrain that `local.is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Receive the arguments, which consists of 8 message columns, `is_send`, `is_receive`, and
        // `kind`. In MemoryGlobal, MemoryLocal, Syscall chips, `is_send`, `is_receive`,
        // `kind` are sent with correct constant values. For a global send interaction,
        // `is_send = 1` and `is_receive = 0` are used. For a global receive interaction,
        // `is_send = 0` and `is_receive = 1` are used. For a memory global interaction,
        // `kind = InteractionKind::Memory` is used. For a syscall global interaction, `kind
        // = InteractionKind::Syscall` is used. Therefore, `is_send`, `is_receive` are
        // already known to be boolean, and `kind` is also known to be a `u8` value.
        builder.receive(
            AirInteraction::new(
                vec![
                    local.message[0].into(),
                    local.message[1].into(),
                    local.message[2].into(),
                    local.message[3].into(),
                    local.message[4].into(),
                    local.message[5].into(),
                    local.message[6].into(),
                    local.message[7].into(),
                    local.is_send.into(),
                    local.is_receive.into(),
                    local.kind.into(),
                ],
                local.is_real.into(),
                InteractionKind::Global,
            ),
            InteractionScope::Local,
        );

        // Evaluate the interaction.
        GlobalInteractionOperation::<AB::F>::eval_single_digest(
            builder,
            local.message.map(Into::into),
            local.interaction,
            local.is_receive.into(),
            local.is_send.into(),
            local.is_real,
            local.kind,
            [local.message_0_16bit_limb, local.message_0_8bit_limb],
        );

        // Evaluate the accumulation.
        GlobalAccumulationOperation::<AB::F>::eval_accumulation(
            builder,
            local.interaction,
            local.is_real,
            local.index,
            local.accumulation,
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::sync::Arc;

    use super::*;
    use crate::io::SP1Stdin;
    use crate::programs::tests::*;
    use crate::utils::generate_records;

    use slop_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, SP1CoreOpts};
    use sp1_hypercube::air::MachineAir;
    use sp1_primitives::SP1Field;

    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_global_generate_trace() {
        let program = simple_program();
        let (records, _) = generate_records::<SP1Field>(
            Arc::new(program),
            SP1Stdin::new(),
            SP1CoreOpts::default(),
            [0; 4],
        )
        .unwrap();

        // Use the last record which should contain global events
        let shard = records.into_iter().last().unwrap();

        let chip: GlobalChip = GlobalChip;

        let trace: RowMajorMatrix<SP1Field> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{mem_event:?}");
        }
    }
}
