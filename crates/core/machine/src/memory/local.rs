use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use crate::utils::{indices_arr, next_power_of_two, zeroed_f_vec};
use crate::{operations::GlobalAccumulationOperation, operations::GlobalInteractionOperation};
use elliptic_curve::bigint::const_assert_eq;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelRefMutIterator;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use rayon_scan::ScanParallelIterator;
use sp1_core_executor::events::ByteLookupEvent;
use sp1_core_executor::events::ByteRecord;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    septic_curve::SepticCurve,
    septic_curve::SepticCurveComplete,
    septic_digest::SepticDigest,
    septic_extension::SepticExtension,
    InteractionKind, Word,
};

/// Creates the column map for the CPU.
const fn make_col_map() -> MemoryLocalCols<usize> {
    let indices_arr = indices_arr::<NUM_MEMORY_LOCAL_INIT_COLS>();
    unsafe { transmute::<[usize; NUM_MEMORY_LOCAL_INIT_COLS], MemoryLocalCols<usize>>(indices_arr) }
}

const MEMORY_LOCAL_COL_MAP: MemoryLocalCols<usize> = make_col_map();

pub const MEMORY_LOCAL_INITIAL_DIGEST_POS: usize =
    MEMORY_LOCAL_COL_MAP.global_accumulation_cols.initial_digest[0].0[0];

pub const MEMORY_LOCAL_INITIAL_DIGEST_POS_COPY: usize = 208;

#[repr(C)]
pub struct Ghost {
    pub v: [usize; MEMORY_LOCAL_INITIAL_DIGEST_POS_COPY],
}

pub const NUM_LOCAL_MEMORY_ENTRIES_PER_ROW: usize = 4;

pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SingleMemoryLocal<T> {
    /// The address of the memory access.
    pub addr: T,

    /// The initial shard of the memory access.
    pub initial_shard: T,

    /// The final shard of the memory access.
    pub final_shard: T,

    /// The initial clk of the memory access.
    pub initial_clk: T,

    /// The final clk of the memory access.
    pub final_clk: T,

    /// The initial value of the memory access.
    pub initial_value: Word<T>,

    /// The final value of the memory access.
    pub final_value: Word<T>,

    /// The global interaction columns for initial access.
    pub initial_global_interaction_cols: GlobalInteractionOperation<T>,

    /// The global interaction columns for final access.
    pub final_global_interaction_cols: GlobalInteractionOperation<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    memory_local_entries: [SingleMemoryLocal<T>; NUM_LOCAL_MEMORY_ENTRIES_PER_ROW],
    pub global_accumulation_cols: GlobalAccumulationOperation<T, 8>,
}

pub struct MemoryLocalChip {}

impl MemoryLocalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        assert_eq!(MEMORY_LOCAL_INITIAL_DIGEST_POS_COPY, MEMORY_LOCAL_INITIAL_DIGEST_POS);
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW).for_each(|events| {
                    let mut row = [F::zero(); NUM_MEMORY_LOCAL_INIT_COLS];
                    let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
                    for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                        let cols = &mut cols.memory_local_entries[k];
                        if k < events.len() {
                            let event = events[k];
                            cols.initial_global_interaction_cols.populate_memory(
                                event.initial_mem_access.shard,
                                event.initial_mem_access.timestamp,
                                event.addr,
                                event.initial_mem_access.value,
                                true,
                                true,
                                &mut blu,
                            );
                            cols.final_global_interaction_cols.populate_memory(
                                event.final_mem_access.shard,
                                event.final_mem_access.timestamp,
                                event.addr,
                                event.final_mem_access.value,
                                false,
                                true,
                                &mut blu,
                            );
                        }
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks =
                    Vec::with_capacity(chunk_size * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

                    let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                    for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                        let cols = &mut cols.memory_local_entries[k];
                        if idx + k < events.len() {
                            let event = &events[idx + k];
                            cols.addr = F::from_canonical_u32(event.addr);
                            cols.initial_shard =
                                F::from_canonical_u32(event.initial_mem_access.shard);
                            cols.final_shard = F::from_canonical_u32(event.final_mem_access.shard);
                            cols.initial_clk =
                                F::from_canonical_u32(event.initial_mem_access.timestamp);
                            cols.final_clk =
                                F::from_canonical_u32(event.final_mem_access.timestamp);
                            cols.initial_value = event.initial_mem_access.value.into();
                            cols.final_value = event.final_mem_access.value.into();
                            cols.is_real = F::one();
                            let mut blu = Vec::new();
                            cols.initial_global_interaction_cols.populate_memory(
                                event.initial_mem_access.shard,
                                event.initial_mem_access.timestamp,
                                event.addr,
                                event.initial_mem_access.value,
                                true,
                                true,
                                &mut blu,
                            );
                            point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                                x: SepticExtension(
                                    cols.initial_global_interaction_cols.x_coordinate.0,
                                ),
                                y: SepticExtension(
                                    cols.initial_global_interaction_cols.y_coordinate.0,
                                ),
                            }));
                            cols.final_global_interaction_cols.populate_memory(
                                event.final_mem_access.shard,
                                event.final_mem_access.timestamp,
                                event.addr,
                                event.final_mem_access.value,
                                false,
                                true,
                                &mut blu,
                            );
                            point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                                x: SepticExtension(
                                    cols.final_global_interaction_cols.x_coordinate.0,
                                ),
                                y: SepticExtension(
                                    cols.final_global_interaction_cols.y_coordinate.0,
                                ),
                            }));
                        } else {
                            cols.initial_global_interaction_cols.populate_dummy();
                            cols.final_global_interaction_cols.populate_dummy();
                        }
                    }
                });
                point_chunks
            })
            .collect::<Vec<_>>();

        let mut points = Vec::with_capacity(1 + events.len() * 2);
        for mut point_chunk in point_chunks {
            points.append(&mut point_chunk);
        }

        if events.is_empty() {
            points = vec![SepticCurveComplete::Affine(SepticDigest::<F>::zero().0)];
        }

        let cumulative_sum = points
            .into_par_iter()
            .with_min_len(1 << 15)
            .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = cumulative_sum.last().unwrap().point();
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker = SepticCurve::<F>::sum_checker_x(final_digest, dummy, final_digest);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;

                    let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                    if idx < nb_rows {
                        let start = NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 * idx;
                        let end = std::cmp::min(
                            NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 * (idx + 1) + 1,
                            cumulative_sum.len(),
                        );
                        cols.global_accumulation_cols.populate_real(
                            &cumulative_sum[start..end],
                            final_digest,
                            final_sum_checker,
                        );
                    } else {
                        for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                            cols.memory_local_entries[k]
                                .initial_global_interaction_cols
                                .populate_dummy();
                            cols.memory_local_entries[k]
                                .final_global_interaction_cols
                                .populate_dummy();
                        }
                        cols.global_accumulation_cols
                            .populate_dummy(final_digest, final_sum_checker);
                    }
                })
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.get_local_mem_events().nth(0).is_some()
        }
    }

    fn commit_scope(&self) -> InteractionScope {
        InteractionScope::Global
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MemoryLocalCols<AB::Var> = (*next).borrow();

        let mut global_interaction_cols = Vec::with_capacity(8);
        let mut local_is_reals = Vec::with_capacity(8);
        let mut next_is_reals = Vec::with_capacity(8);

        for local in local.memory_local_entries.iter() {
            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            let mut values =
                vec![local.initial_shard.into(), local.initial_clk.into(), local.addr.into()];
            values.extend(local.initial_value.map(Into::into));
            builder.receive(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );

            GlobalInteractionOperation::<AB::F>::eval_single_digest_memory(
                builder,
                local.initial_shard.into(),
                local.initial_clk.into(),
                local.addr.into(),
                local.initial_value.map(Into::into).0,
                local.initial_global_interaction_cols,
                true,
                local.is_real,
            );

            global_interaction_cols.push(local.initial_global_interaction_cols);
            local_is_reals.push(local.is_real);

            let mut values =
                vec![local.final_shard.into(), local.final_clk.into(), local.addr.into()];
            values.extend(local.final_value.map(Into::into));
            builder.send(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );

            GlobalInteractionOperation::<AB::F>::eval_single_digest_memory(
                builder,
                local.final_shard.into(),
                local.final_clk.into(),
                local.addr.into(),
                local.final_value.map(Into::into).0,
                local.final_global_interaction_cols,
                false,
                local.is_real,
            );

            global_interaction_cols.push(local.final_global_interaction_cols);
            local_is_reals.push(local.is_real);
        }

        for next in next.memory_local_entries.iter() {
            next_is_reals.push(next.is_real);
            next_is_reals.push(next.is_real);
        }

        GlobalAccumulationOperation::<AB::F, 8>::eval_accumulation(
            builder,
            global_interaction_cols
                .try_into()
                .unwrap_or_else(|_| panic!("There should be 8 interactions")),
            local_is_reals.try_into().unwrap_or_else(|_| panic!("There should be 8 interactions")),
            next_is_reals.try_into().unwrap_or_else(|_| panic!("There should be 8 interactions")),
            local.global_accumulation_cols,
            next.global_accumulation_cols,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::thread_rng;
    use rand::Rng;
    use sp1_core_executor::events::{MemoryLocalEvent, MemoryRecord};
    use sp1_core_executor::{programs::tests::simple_program, ExecutionRecord, Executor};
    use sp1_stark::{
        air::{InteractionScope, MachineAir},
        baby_bear_poseidon2::BabyBearPoseidon2,
        debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
    };

    use crate::{
        memory::MemoryLocalChip, riscv::RiscvAir,
        syscall::precompiles::sha256::extend_tests::sha_extend_program, utils::setup_logger,
    };

    #[test]
    fn test_local_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.records[0].clone();

        let chip: MemoryLocalChip = MemoryLocalChip::new();

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    #[test]
    fn test_memory_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine: StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
            RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SP1CoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts, None);

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Memory],
            InteractionScope::Global,
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SP1CoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts, None);

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Byte],
            InteractionScope::Global,
        );
    }

    #[cfg(feature = "sys")]
    fn get_test_execution_record() -> ExecutionRecord {
        let cpu_local_memory_access = (0..=255)
            .flat_map(|_| {
                [{
                    let addr = thread_rng().gen_range(0..BabyBear::ORDER_U32);
                    let init_value = thread_rng().gen_range(0..u32::MAX);
                    let init_shard = thread_rng().gen_range(0..(1u32 << 16));
                    let init_timestamp = thread_rng().gen_range(0..(1u32 << 24));
                    let final_value = thread_rng().gen_range(0..u32::MAX);
                    let final_timestamp = thread_rng().gen_range(0..(1u32 << 24));
                    let final_shard = thread_rng().gen_range(0..(1u32 << 16));
                    MemoryLocalEvent {
                        addr,
                        initial_mem_access: MemoryRecord {
                            shard: init_shard,
                            timestamp: init_timestamp,
                            value: init_value,
                        },
                        final_mem_access: MemoryRecord {
                            shard: final_shard,
                            timestamp: final_timestamp,
                            value: final_value,
                        },
                    }
                }]
            })
            .collect::<Vec<_>>();
        ExecutionRecord { cpu_local_memory_access, ..Default::default() }
    }

    #[cfg(feature = "sys")]
    #[test]
    fn test_generate_trace_ffi_eq_rust() {
        let record = get_test_execution_record();
        let chip = MemoryLocalChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&record, &mut ExecutionRecord::default());
        let trace_ffi = generate_trace_ffi(&record, trace.height());

        assert_eq!(trace_ffi, trace);
    }

    #[cfg(feature = "sys")]
    fn generate_trace_ffi(input: &ExecutionRecord, height: usize) -> RowMajorMatrix<BabyBear> {
        type F = BabyBear;
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let padded_nb_rows = height;
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks =
                    Vec::with_capacity(chunk_size * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;
                    let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                    for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                        let cols = &mut cols.memory_local_entries[k];
                        if idx + k < events.len() {
                            unsafe {
                                crate::sys::memory_local_event_to_row_babybear(
                                    events[idx + k],
                                    cols,
                                );
                            }
                            point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                                x: SepticExtension(
                                    cols.initial_global_interaction_cols.x_coordinate.0,
                                ),
                                y: SepticExtension(
                                    cols.initial_global_interaction_cols.y_coordinate.0,
                                ),
                            }));
                            point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                                x: SepticExtension(
                                    cols.final_global_interaction_cols.x_coordinate.0,
                                ),
                                y: SepticExtension(
                                    cols.final_global_interaction_cols.y_coordinate.0,
                                ),
                            }));
                        } else {
                            cols.initial_global_interaction_cols.populate_dummy();
                            cols.final_global_interaction_cols.populate_dummy();
                        }
                    }
                });
                point_chunks
            })
            .collect::<Vec<_>>();

        let mut points = Vec::with_capacity(1 + events.len() * 2);
        for mut point_chunk in point_chunks {
            points.append(&mut point_chunk);
        }

        if events.is_empty() {
            points = vec![SepticCurveComplete::Affine(SepticDigest::<F>::zero().0)];
        }

        let cumulative_sum = points
            .into_par_iter()
            .with_min_len(1 << 15)
            .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = cumulative_sum.last().unwrap().point();
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker = SepticCurve::<F>::sum_checker_x(final_digest, dummy, final_digest);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;

                    let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                    if idx < nb_rows {
                        let start = NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 * idx;
                        let end = std::cmp::min(
                            NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 * (idx + 1) + 1,
                            cumulative_sum.len(),
                        );
                        cols.global_accumulation_cols.populate_real(
                            &cumulative_sum[start..end],
                            final_digest,
                            final_sum_checker,
                        );
                    } else {
                        for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                            cols.memory_local_entries[k]
                                .initial_global_interaction_cols
                                .populate_dummy();
                            cols.memory_local_entries[k]
                                .final_global_interaction_cols
                                .populate_dummy();
                        }
                        cols.global_accumulation_cols
                            .populate_dummy(final_digest, final_sum_checker);
                    }
                })
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }
}
