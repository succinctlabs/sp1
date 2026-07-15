use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use crate::{air::WordAirBuilder, utils::next_multiple_of_32};
use slop_air::{Air, BaseAir, GlobalBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use sp1_core_executor::{
    events::{ByteRecord, MemoryLocalEvent},
    ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    InteractionKind, Word,
};
use struct_reflection::{StructReflection, StructReflectionHelper};

pub const NUM_LOCAL_MEMORY_ENTRIES_PER_ROW: usize = 1;
pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct SingleMemoryLocal<T: Copy> {
    /// The address of the memory access.
    pub addr: [T; 3],

    /// The high bits of initial clk of the memory access.
    pub initial_clk_high: T,

    /// The high bits of final clk of the memory access.
    pub final_clk_high: T,

    /// The low bits of initial clk of the memory access.
    pub initial_clk_low: T,

    /// The low bits of final clk of the memory access.
    pub final_clk_low: T,

    /// The initial value of the memory access.
    pub initial_value: Word<T>,

    /// The final value of the memory access.
    pub final_value: Word<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct MemoryLocalCols<T: Copy> {
    memory_local_entries: [SingleMemoryLocal<T>; NUM_LOCAL_MEMORY_ENTRIES_PER_ROW],
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
        0
    }
}

fn nb_rows(count: usize) -> usize {
    if NUM_LOCAL_MEMORY_ENTRIES_PER_ROW > 1 {
        count.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
    } else {
        count
    }
}

fn local_mem_events(input: &ExecutionRecord) -> impl Iterator<Item = &MemoryLocalEvent> {
    input.shard_data.iter().flat_map(|sd| sd.entries.iter())
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "MemoryLocal"
    }

    fn global_width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        local_mem_events(input).for_each(|mem_event| {
            let mut blu = Vec::with_capacity(11); // 3 + 4 + 4
            blu.add_u16_range_check((mem_event.addr & 0xFFFF) as u16);
            blu.add_u16_range_check(((mem_event.addr >> 16) & 0xFFFF) as u16);
            blu.add_u16_range_check(((mem_event.addr >> 32) & 0xFFFF) as u16);
            blu.add_u16_range_checks_field::<F>(&Word::from(mem_event.initial_mem_access.value).0);
            blu.add_u16_range_checks_field::<F>(&Word::from(mem_event.final_mem_access.value).0);
            output.add_byte_lookup_events(blu);
        });
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let count = local_mem_events(input).count();
        let nb_rows = nb_rows(count);
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_trace_into(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [MaybeUninit<F>],
    ) {
    }

    fn generate_global_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the trace rows for each event.
        let events = local_mem_events(input).collect::<Vec<_>>();
        let nb_rows = nb_rows(events.len());
        let padded_nb_rows = <MemoryLocalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        unsafe {
            let padding_start = nb_rows * NUM_MEMORY_LOCAL_INIT_COLS;
            let padding_size = (padded_nb_rows - nb_rows) * NUM_MEMORY_LOCAL_INIT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, nb_rows * NUM_MEMORY_LOCAL_INIT_COLS)
        };

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                    let cols = &mut cols.memory_local_entries[k];
                    if idx + k < events.len() {
                        let event = &events[idx + k];
                        cols.addr = [
                            F::from_canonical_u64(event.addr & 0xFFFF),
                            F::from_canonical_u64((event.addr >> 16) & 0xFFFF),
                            F::from_canonical_u64((event.addr >> 32) & 0xFFFF),
                        ];
                        cols.initial_clk_high = F::from_canonical_u32(
                            (event.initial_mem_access.timestamp >> 24) as u32,
                        );
                        cols.final_clk_high =
                            F::from_canonical_u32((event.final_mem_access.timestamp >> 24) as u32);
                        cols.initial_clk_low = F::from_canonical_u32(
                            (event.initial_mem_access.timestamp & 0xFFFFFF) as u32,
                        );
                        cols.final_clk_low = F::from_canonical_u32(
                            (event.final_mem_access.timestamp & 0xFFFFFF) as u32,
                        );
                        cols.initial_value = event.initial_mem_access.value.into();
                        cols.final_value = event.final_mem_access.value.into();
                        cols.is_real = F::one();
                    }
                }
            });
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            local_mem_events(shard).nth(0).is_some()
        }
    }

    fn column_names(&self) -> Vec<String> {
        MemoryLocalCols::<F>::struct_reflection().unwrap()
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let global = builder.global();
        let local = global.row_slice(0);
        let local: &MemoryLocalCols<AB::Var> = (*local).borrow();

        for local in local.memory_local_entries.iter() {
            // Constrain that `local.is_real` is boolean.
            builder.assert_bool(local.is_real);

            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            builder.slice_range_check_u16(&local.addr, local.is_real);

            builder.slice_range_check_u16(&local.initial_value.0, local.is_real);
            let mut values = vec![local.initial_clk_high.into(), local.initial_clk_low.into()];
            values.extend(local.addr.map(Into::into));
            values.extend(local.initial_value.map(Into::into));
            builder.send(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );
            builder.receive(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Global,
            );

            builder.slice_range_check_u16(&local.final_value.0, local.is_real);
            let mut values = vec![local.final_clk_high.into(), local.final_clk_low.into()];
            values.extend(local.addr.map(Into::into));
            values.extend(local.final_value.map(Into::into));
            builder.receive(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );
            builder.send(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Global,
            );
        }
    }
}

// #[cfg(test)]
// mod tests {
//     #![allow(clippy::print_stdout)]

//     use crate::programs::tests::*;
//     use crate::{
//         memory::MemoryLocalChip, riscv::RiscvAir,
//         syscall::precompiles::sha256::extend_tests::sha_extend_program, utils::setup_logger,
//     };
//     use sp1_primitives::SP1Field;
//     use slop_matrix::dense::RowMajorMatrix;
//     use sp1_core_executor::{ExecutionRecord, Executor, Trace};
//     use sp1_hypercube::{
//         air::{InteractionScope, MachineAir},
//         koala_bear_poseidon2::SP1InnerPcs,
//         debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
//     };

//     #[test]
//     fn test_local_memory_generate_trace() {
//         let program = simple_program();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let shard = runtime.records[0].clone();

//         let chip: MemoryLocalChip = MemoryLocalChip::new();

//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values);

//         for mem_event in shard.global_memory_finalize_events {
//             println!("{mem_event:?}");
//         }
//     }

//     #[test]
//     fn test_memory_lookup_interactions() {
//         setup_logger();
//         let program = sha_extend_program();
//         let program_clone = program.clone();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let machine: StarkMachine<SP1InnerPcs, RiscvAir<SP1Field>> =
//             RiscvAir::machine(SP1InnerPcs::new());
//         let (pkey, _) = machine.setup(&program_clone);
//         let opts = SP1CoreOpts::default();
//         machine.generate_dependencies(
//             &mut runtime.records.clone().into_iter().map(|r| *r).collect::<Vec<_>>(),
//             &opts,
//             None,
//         );

//         let shards = runtime.records;
//         for shard in shards.clone() {
//             debug_interactions_with_all_chips::<SP1InnerPcs, RiscvAir<SP1Field>>(
//                 &machine,
//                 &pkey,
//                 &[*shard],
//                 vec![InteractionKind::Memory],
//                 InteractionScope::Local,
//             );
//         }
//         debug_interactions_with_all_chips::<SP1InnerPcs, RiscvAir<SP1Field>>(
//             &machine,
//             &pkey,
//             &shards.into_iter().map(|r| *r).collect::<Vec<_>>(),
//             vec![InteractionKind::Memory],
//             InteractionScope::Global,
//         );
//     }

//     #[test]
//     fn test_byte_lookup_interactions() {
//         setup_logger();
//         let program = sha_extend_program();
//         let program_clone = program.clone();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let machine = RiscvAir::machine(SP1InnerPcs::new());
//         let (pkey, _) = machine.setup(&program_clone);
//         let opts = SP1CoreOpts::default();
//         machine.generate_dependencies(
//             &mut runtime.records.clone().into_iter().map(|r| *r).collect::<Vec<_>>(),
//             &opts,
//             None,
//         );

//         let shards = runtime.records;
//         for shard in shards.clone() {
//             debug_interactions_with_all_chips::<SP1InnerPcs, RiscvAir<SP1Field>>(
//                 &machine,
//                 &pkey,
//                 &[*shard],
//                 vec![InteractionKind::Memory],
//                 InteractionScope::Local,
//             );
//         }
//         debug_interactions_with_all_chips::<SP1InnerPcs, RiscvAir<SP1Field>>(
//             &machine,
//             &pkey,
//             &shards.into_iter().map(|r| *r).collect::<Vec<_>>(),
//             vec![InteractionKind::Byte],
//             InteractionScope::Global,
//         );
//     }

//     #[cfg(feature = "sys")]
//     fn get_test_execution_record() -> ExecutionRecord {
//         use slop_algebra::PrimeField32;
//         use rand::{thread_rng, Rng};
//         use sp1_core_executor::events::{MemoryLocalEvent, MemoryRecord};

//         let cpu_local_memory_access = (0..=255)
//             .flat_map(|_| {
//                 [{
//                     let addr = thread_rng().gen_range(0..SP1Field::ORDER_U32);
//                     let init_value = thread_rng().gen_range(0..u32::MAX);
//                     let init_shard = thread_rng().gen_range(0..(1u32 << 16));
//                     let init_timestamp = thread_rng().gen_range(0..(1u32 << 24));
//                     let final_value = thread_rng().gen_range(0..u32::MAX);
//                     let final_timestamp = thread_rng().gen_range(0..(1u32 << 24));
//                     let final_shard = thread_rng().gen_range(0..(1u32 << 16));
//                     MemoryLocalEvent {
//                         addr,
//                         initial_mem_access: MemoryRecord {
//                             shard: init_shard,
//                             timestamp: init_timestamp,
//                             value: init_value,
//                         },
//                         final_mem_access: MemoryRecord {
//                             shard: final_shard,
//                             timestamp: final_timestamp,
//                             value: final_value,
//                         },
//                     }
//                 }]
//             })
//             .collect::<Vec<_>>();
//         ExecutionRecord { cpu_local_memory_access, ..Default::default() }
//     }

//     #[cfg(feature = "sys")]
//     #[test]
//     fn test_generate_trace_ffi_eq_rust() {
//         use slop_matrix::Matrix;

//         let record = get_test_execution_record();
//         let chip = MemoryLocalChip::new();
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&record, &mut ExecutionRecord::default());
//         let trace_ffi = generate_trace_ffi(&record, trace.height());

//         assert_eq!(trace_ffi, trace);
//     }

//     #[cfg(feature = "sys")]
//     fn generate_trace_ffi(input: &ExecutionRecord, height: usize) -> RowMajorMatrix<SP1Field> {
//         use std::borrow::BorrowMut;

//         use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

//         use crate::{
//             memory::{
//                 MemoryLocalCols, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, NUM_MEMORY_LOCAL_INIT_COLS,
//             },
//             utils::zeroed_f_vec,
//         };

//         use sp1_primitives::SP1Field;
// type F = SP1Field;
//         // Generate the trace rows for each event.
//         let events = local_mem_events(input).collect::<Vec<_>>();
//         let nb_rows = events.len().div_ceil(4);
//         let padded_nb_rows = height;
//         let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
//         let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

//         let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
//             .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
//             .collect::<Vec<_>>();

//         chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
//             rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
//                 let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;
//                 let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
//                 for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
//                     let cols = &mut cols.memory_local_entries[k];
//                     if idx + k < events.len() {
//                         unsafe {
//                             crate::sys::memory_local_event_to_row_koalabear(events[idx + k],
// cols);                         }
//                     }
//                 }
//             });
//         });

//         // Convert the trace to a row major matrix.
//         RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
//     }
// }
