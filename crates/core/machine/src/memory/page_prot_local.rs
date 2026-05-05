use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use crate::utils::next_multiple_of_32;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use sp1_core_executor::{events::GlobalInteractionEvent, ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    InteractionKind,
};
use sp1_primitives::consts::split_page_idx;

pub const NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW: usize = 1;
pub(crate) const NUM_PAGE_PROT_LOCAL_INIT_COLS: usize = size_of::<PageProtLocalCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct SinglePageProtLocal<T: Copy> {
    /// The idx of the page.
    pub page_idx: [T; 3],

    /// The high bits of initial clk of the page prot access.
    pub initial_clk_high: T,

    /// The high bits of final clk of the page prot access.
    pub final_clk_high: T,

    /// The low bits of initial clk of the page prot access.
    pub initial_clk_low: T,

    /// The low bits of final clk of the page prot access.
    pub final_clk_low: T,

    /// The initial value of the page prot access.
    pub initial_page_prot: T,

    /// The final value of the memory access.
    pub final_page_prot: T,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PageProtLocalCols<T: Copy> {
    page_prot_local_entries: [SinglePageProtLocal<T>; NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW],
}

#[derive(Default)]
pub struct PageProtLocalChip;

impl<F> BaseAir<F> for PageProtLocalChip {
    fn width(&self) -> usize {
        NUM_PAGE_PROT_LOCAL_INIT_COLS
    }
}

fn nb_rows(count: usize) -> usize {
    if NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW > 1 {
        count.div_ceil(NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW)
    } else {
        count
    }
}

impl<F: PrimeField32> MachineAir<F> for PageProtLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "PageProtLocal"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let count = input.get_local_page_prot_events().count();

        if input.public_values.is_untrusted_programs_enabled == 0 {
            assert!(count == 0);
        }
        let nb_rows = nb_rows(count);
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let mut events = Vec::new();

        input.get_local_page_prot_events().for_each(|page_prot_event| {
            let page_idx = split_page_idx(page_prot_event.page_idx);

            events.push(GlobalInteractionEvent {
                message: [
                    (page_prot_event.initial_page_prot_access.timestamp >> 24) as u32,
                    (page_prot_event.initial_page_prot_access.timestamp & 0xFFFFFF) as u32,
                    page_idx[0] as u32,
                    page_idx[1] as u32,
                    page_idx[2] as u32,
                    page_prot_event.initial_page_prot_access.page_prot as u32,
                    0,
                    0,
                ],
                is_receive: true,
                kind: InteractionKind::PageProtAccess as u8,
            });
            events.push(GlobalInteractionEvent {
                message: [
                    (page_prot_event.final_page_prot_access.timestamp >> 24) as u32,
                    (page_prot_event.final_page_prot_access.timestamp & 0xFFFFFF) as u32,
                    page_idx[0] as u32,
                    page_idx[1] as u32,
                    page_idx[2] as u32,
                    page_prot_event.final_page_prot_access.page_prot as u32,
                    0,
                    0,
                ],
                is_receive: false,
                kind: InteractionKind::PageProtAccess as u8,
            });
        });

        output.global_interaction_events.extend(events);
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the trace rows for each event.
        let events = input.get_local_page_prot_events().collect::<Vec<_>>();

        if input.public_values.is_untrusted_programs_enabled == 0 {
            assert!(events.is_empty());
        }
        let nb_rows = nb_rows(events.len());
        let padded_nb_rows = <PageProtLocalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        unsafe {
            let padding_start = nb_rows * NUM_PAGE_PROT_LOCAL_INIT_COLS;
            let padding_size = (padded_nb_rows - nb_rows) * NUM_PAGE_PROT_LOCAL_INIT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, nb_rows * NUM_PAGE_PROT_LOCAL_INIT_COLS)
        };

        let mut chunks = values[..nb_rows * NUM_PAGE_PROT_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_PAGE_PROT_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_PAGE_PROT_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                let idx = (i * chunk_size + j) * NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW;

                let cols: &mut PageProtLocalCols<F> = row.borrow_mut();
                for k in 0..NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW {
                    let cols = &mut cols.page_prot_local_entries[k];
                    if idx + k < events.len() {
                        let event = &events[idx + k];
                        cols.page_idx = [
                            F::from_canonical_u64((event.page_idx) & 0xF),
                            F::from_canonical_u64((event.page_idx >> 4) & 0xFFFF),
                            F::from_canonical_u64((event.page_idx >> 20) & 0xFFFF),
                        ];
                        cols.initial_clk_high = F::from_canonical_u32(
                            (event.initial_page_prot_access.timestamp >> 24) as u32,
                        );
                        cols.final_clk_high = F::from_canonical_u32(
                            (event.final_page_prot_access.timestamp >> 24) as u32,
                        );
                        cols.initial_clk_low = F::from_canonical_u32(
                            (event.initial_page_prot_access.timestamp & 0xFFFFFF) as u32,
                        );
                        cols.final_clk_low = F::from_canonical_u32(
                            (event.final_page_prot_access.timestamp & 0xFFFFFF) as u32,
                        );
                        cols.initial_page_prot =
                            F::from_canonical_u8(event.initial_page_prot_access.page_prot);
                        cols.final_page_prot =
                            F::from_canonical_u8(event.final_page_prot_access.page_prot);
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
            shard.get_local_page_prot_events().nth(0).is_some()
                && shard.program.enable_untrusted_programs
        }
    }
}

impl<AB> Air<AB> for PageProtLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PageProtLocalCols<AB::Var> = (*local).borrow();

        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::one(),
        );

        for local in local.page_prot_local_entries.iter() {
            // Constrain that `local.is_real` is boolean.
            builder.assert_bool(local.is_real);

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            let mut values = vec![local.initial_clk_high.into(), local.initial_clk_low.into()];
            values.extend(local.page_idx.map(Into::into));
            values.push(local.initial_page_prot.into());
            builder.receive(
                AirInteraction::new(
                    values.clone(),
                    local.is_real.into(),
                    InteractionKind::PageProtAccess,
                ),
                InteractionScope::Local,
            );

            // Send the "receive interaction" to the global table.
            builder.send(
                AirInteraction::new(
                    vec![
                        local.initial_clk_high.into(),
                        local.initial_clk_low.into(),
                        local.page_idx[0].into(),
                        local.page_idx[1].into(),
                        local.page_idx[2].into(),
                        local.initial_page_prot.into(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                        AB::Expr::one(),
                        AB::Expr::from_canonical_u8(InteractionKind::PageProtAccess as u8),
                    ],
                    local.is_real.into(),
                    InteractionKind::Global,
                ),
                InteractionScope::Local,
            );

            // Send the "send interaction" to the global table.
            builder.send(
                AirInteraction::new(
                    vec![
                        local.final_clk_high.into(),
                        local.final_clk_low.into(),
                        local.page_idx[0].into(),
                        local.page_idx[1].into(),
                        local.page_idx[2].into(),
                        local.final_page_prot.into(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                        AB::Expr::one(),
                        AB::Expr::zero(),
                        AB::Expr::from_canonical_u8(InteractionKind::PageProtAccess as u8),
                    ],
                    local.is_real.into(),
                    InteractionKind::Global,
                ),
                InteractionScope::Local,
            );

            let mut values = vec![local.final_clk_high.into(), local.final_clk_low.into()];
            values.extend(local.page_idx.map(Into::into));
            values.push(local.final_page_prot.into());
            builder.send(
                AirInteraction::new(
                    values.clone(),
                    local.is_real.into(),
                    InteractionKind::PageProtAccess,
                ),
                InteractionScope::Local,
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
//     use slop_baby_bear::BabyBear;
//     use slop_matrix::dense::RowMajorMatrix;
//     use sp1_core_executor::{ExecutionRecord, Executor, Trace};
//     use sp1_stark::{
//         air::{InteractionScope, MachineAir},
//         baby_bear_poseidon2::BabyBearPoseidon2,
//         debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
//     };

//     #[test]
//     fn test_local_memory_generate_trace() {
//         let program = simple_program();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let shard = runtime.records[0].clone();

//         let chip: MemoryLocalChip = MemoryLocalChip::new();

//         let trace: RowMajorMatrix<BabyBear> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values);

//         for mem_event in shard.global_memory_finalize_events {
//             println!("{:?}", mem_event);
//         }
//     }

//     #[test]
//     fn test_memory_lookup_interactions() {
//         setup_logger();
//         let program = sha_extend_program();
//         let program_clone = program.clone();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let machine: StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
//             RiscvAir::machine(BabyBearPoseidon2::new());
//         let (pkey, _) = machine.setup(&program_clone);
//         let opts = SP1CoreOpts::default();
//         machine.generate_dependencies(
//             &mut runtime.records.clone().into_iter().map(|r| *r).collect::<Vec<_>>(),
//             &opts,
//             None,
//         );

//         let shards = runtime.records;
//         for shard in shards.clone() {
//             debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
//                 &machine,
//                 &pkey,
//                 &[*shard],
//                 vec![InteractionKind::Memory],
//                 InteractionScope::Local,
//             );
//         }
//         debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
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
//         let machine = RiscvAir::machine(BabyBearPoseidon2::new());
//         let (pkey, _) = machine.setup(&program_clone);
//         let opts = SP1CoreOpts::default();
//         machine.generate_dependencies(
//             &mut runtime.records.clone().into_iter().map(|r| *r).collect::<Vec<_>>(),
//             &opts,
//             None,
//         );

//         let shards = runtime.records;
//         for shard in shards.clone() {
//             debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
//                 &machine,
//                 &pkey,
//                 &[*shard],
//                 vec![InteractionKind::Memory],
//                 InteractionScope::Local,
//             );
//         }
//         debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
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
//                     let addr = thread_rng().gen_range(0..BabyBear::ORDER_U32);
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
//         let trace: RowMajorMatrix<BabyBear> =
//             chip.generate_trace(&record, &mut ExecutionRecord::default());
//         let trace_ffi = generate_trace_ffi(&record, trace.height());

//         assert_eq!(trace_ffi, trace);
//     }

//     #[cfg(feature = "sys")]
//     fn generate_trace_ffi(input: &ExecutionRecord, height: usize) -> RowMajorMatrix<BabyBear> {
//         use std::borrow::BorrowMut;

//         use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

//         use crate::{
//             memory::{
//                 MemoryLocalCols, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, NUM_MEMORY_LOCAL_INIT_COLS,
//             },
//             utils::zeroed_f_vec,
//         };

//         type F = BabyBear;
//         // Generate the trace rows for each event.
//         let events = input.get_local_mem_events().collect::<Vec<_>>();
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
//                             crate::sys::memory_local_event_to_row_babybear(events[idx + k],
// cols);                         }
//                     }
//                 }
//             });
//         });

//         // Convert the trace to a row major matrix.
//         RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
//     }
// }
