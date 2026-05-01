use super::MemoryChipType;
use crate::{
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{
        IsZeroOperation, IsZeroOperationInput, LtOperationUnsigned, LtOperationUnsignedInput,
    },
    utils::next_multiple_of_32,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator, ParallelSlice,
    ParallelSliceMut,
};
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, GlobalInteractionEvent, PageProtInitializeFinalizeEvent,
    },
    ByteOpcode, ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind, Word,
};
use sp1_primitives::consts::{split_page_idx, DEFAULT_PAGE_PROT};
use std::{iter::once, mem::MaybeUninit};

/// A memory chip that can initialize or finalize values in memory.
pub struct PageProtGlobalChip {
    pub kind: MemoryChipType,
}

impl PageProtGlobalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }
}

impl<F> BaseAir<F> for PageProtGlobalChip {
    fn width(&self) -> usize {
        NUM_PAGE_PROT_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for PageProtGlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        match self.kind {
            MemoryChipType::Initialize => "PageProtGlobalInit",
            MemoryChipType::Finalize => "PageProtGlobalFinalize",
        }
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut page_prot_events = match self.kind {
            MemoryChipType::Initialize => input.global_page_prot_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_page_prot_finalize_events.clone(),
        };

        let is_receive = match self.kind {
            MemoryChipType::Initialize => false,
            MemoryChipType::Finalize => true,
        };

        match self.kind {
            MemoryChipType::Initialize => {
                output.public_values.global_page_prot_init_count += page_prot_events.len() as u32;
            }
            MemoryChipType::Finalize => {
                output.public_values.global_page_prot_finalize_count +=
                    page_prot_events.len() as u32;
            }
        };

        let previous_page_idx = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_page_idx,
            MemoryChipType::Finalize => input.public_values.previous_finalize_page_idx,
        };

        page_prot_events.sort_by_key(|event| event.page_idx);

        let chunk_size = std::cmp::max(page_prot_events.len() / num_cpus::get(), 1);
        let indices = (0..page_prot_events.len()).collect::<Vec<_>>();
        let blu_batches = indices
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut blu: Vec<ByteLookupEvent> = Vec::new();
                let mut row = [F::zero(); NUM_PAGE_PROT_INIT_COLS];
                let cols: &mut PageProtInitCols<F> = row.as_mut_slice().borrow_mut();
                chunk.iter().for_each(|&i| {
                    let page_idx = page_prot_events[i].page_idx;
                    let page_prot = page_prot_events[i].page_prot;
                    let prev_page_idx =
                        if i == 0 { previous_page_idx } else { page_prot_events[i - 1].page_idx };

                    let prev_page_idx_limbs = split_page_idx(prev_page_idx);
                    let page_idx_limbs = split_page_idx(page_idx);

                    blu.add_bit_range_check(page_prot as u16, 3);
                    blu.add_bit_range_check(prev_page_idx_limbs[0], 4);
                    blu.add_u16_range_checks(&[prev_page_idx_limbs[1], prev_page_idx_limbs[2]]);
                    blu.add_bit_range_check(page_idx_limbs[0], 4);
                    blu.add_u16_range_checks(&[page_idx_limbs[1], page_idx_limbs[2]]);
                    if i != 0 || prev_page_idx != 0 || page_idx != 0 {
                        cols.lt_cols.populate_unsigned(
                            &mut blu,
                            1,
                            prev_page_idx << 12,
                            page_idx << 12,
                        );
                    }
                });
                blu
            })
            .collect::<Vec<_>>();
        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());

        let events = page_prot_events.into_iter().map(|event| {
            let interaction_clk_high = if is_receive { (event.timestamp >> 24) as u32 } else { 0 };
            let interaction_clk_low =
                if is_receive { (event.timestamp & 0xFFFFFF) as u32 } else { 0 };

            let page_idx_limbs = split_page_idx(event.page_idx);

            GlobalInteractionEvent {
                message: [
                    interaction_clk_high,
                    interaction_clk_low,
                    page_idx_limbs[0].into(),
                    page_idx_limbs[1].into(),
                    page_idx_limbs[2].into(),
                    event.page_prot.into(),
                    0,
                    0,
                ],
                is_receive,
                kind: InteractionKind::PageProtAccess as u8,
            }
        });
        output.global_interaction_events.extend(events);
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = match self.kind {
            MemoryChipType::Initialize => &input.global_page_prot_initialize_events,
            MemoryChipType::Finalize => &input.global_page_prot_finalize_events,
        };
        if input.public_values.is_untrusted_programs_enabled == 0 {
            assert!(events.is_empty());
        }
        let nb_rows = events.len();

        let size_log2 = input.fixed_log2_rows::<F, Self>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let mut page_prot_events = match self.kind {
            MemoryChipType::Initialize => input.global_page_prot_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_page_prot_finalize_events.clone(),
        };

        let previous_page_idx = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_page_idx,
            MemoryChipType::Finalize => input.public_values.previous_finalize_page_idx,
        };

        page_prot_events.sort_by_key(|event| event.page_idx);
        if input.public_values.is_untrusted_programs_enabled == 0 {
            assert!(page_prot_events.is_empty());
        }

        let padded_nb_rows = <PageProtGlobalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = page_prot_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_PAGE_PROT_INIT_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_PAGE_PROT_INIT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_PAGE_PROT_INIT_COLS)
        };

        values
            .par_chunks_exact_mut(NUM_PAGE_PROT_INIT_COLS)
            .zip(page_prot_events.par_iter())
            .for_each(|(row, event)| {
                let cols: &mut PageProtInitCols<F> = row.borrow_mut();
                let PageProtInitializeFinalizeEvent { page_idx, page_prot, timestamp } =
                    event.to_owned();

                let page_idx_limbs = split_page_idx(page_idx);
                cols.page_idx[0] = F::from_canonical_u16(page_idx_limbs[0]);
                cols.page_idx[1] = F::from_canonical_u16(page_idx_limbs[1]);
                cols.page_idx[2] = F::from_canonical_u16(page_idx_limbs[2]);
                cols.clk_high = F::from_canonical_u32((timestamp >> 24) as u32);
                cols.clk_low = F::from_canonical_u32((timestamp & 0xFFFFFF) as u32);
                cols.page_prot = F::from_canonical_u8(page_prot);
                cols.is_real = F::one();
            });

        let mut blu: Vec<ByteLookupEvent> = vec![];
        for i in 0..page_prot_events.len() {
            let row_start = i * NUM_PAGE_PROT_INIT_COLS;
            let row = &mut values[row_start..row_start + NUM_PAGE_PROT_INIT_COLS];
            let cols: &mut PageProtInitCols<F> = row.borrow_mut();

            let page_idx = page_prot_events[i].page_idx;
            let prev_page_idx =
                if i == 0 { previous_page_idx } else { page_prot_events[i - 1].page_idx };
            if prev_page_idx == 0 && i != 0 {
                cols.prev_valid = F::zero();
            } else {
                cols.prev_valid = F::one();
            }
            cols.index = F::from_canonical_u32(i as u32);
            let prev_page_idx_limbs = split_page_idx(prev_page_idx);
            cols.prev_page_idx[0] = F::from_canonical_u16(prev_page_idx_limbs[0]);
            cols.prev_page_idx[1] = F::from_canonical_u16(prev_page_idx_limbs[1]);
            cols.prev_page_idx[2] = F::from_canonical_u16(prev_page_idx_limbs[2]);
            cols.is_page_idxes_zero.populate_from_field_element(
                cols.prev_page_idx[0]
                    + cols.prev_page_idx[1]
                    + cols.prev_page_idx[2]
                    + cols.page_idx[0]
                    + cols.page_idx[1]
                    + cols.page_idx[2],
            );
            cols.is_index_zero.populate(i as u64);
            if prev_page_idx != 0 || page_idx != 0 || i != 0 {
                cols.is_comp = F::one();
                // The page_idx values need to be shifted by 12 bits, since cols.prev_page_idx and
                // cols.page_idx are 4 bit limbs. The lt_cols operation will split it's
                // operands to 16 bit limbs.
                cols.lt_cols.populate_unsigned(&mut blu, 1, prev_page_idx << 12, page_idx << 12);
            } else {
                cols.is_comp = F::zero();
                cols.lt_cols = LtOperationUnsigned::<F>::default();
            }
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.kind {
                MemoryChipType::Initialize => {
                    !shard.global_page_prot_initialize_events.is_empty()
                        && shard.program.enable_untrusted_programs
                }
                MemoryChipType::Finalize => {
                    !shard.global_page_prot_finalize_events.is_empty()
                        && shard.program.enable_untrusted_programs
                }
            }
        }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PageProtInitCols<T: Copy> {
    /// The top bits of the timestamp of the page prot access.
    pub clk_high: T,

    /// The low bits of the timestamp of the page prot access.
    pub clk_low: T,

    /// The index of the page prot access.
    pub index: T,

    /// The address of the previous page prot access.
    pub prev_page_idx: [T; 3],

    /// The address of the page prot access.
    pub page_idx: [T; 3],

    /// Comparison assertions for address to be strictly increasing.
    pub lt_cols: LtOperationUnsigned<T>,

    /// The value of the page prot bitmap.
    pub page_prot: T,

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether or not we are making the assertion `prev_page_idx < page_idx`.
    pub is_comp: T,

    /// The validity of previous state.
    /// The unique invalid state is when the chip only initializes page index 0 once.
    pub prev_valid: T,

    /// A witness to assert whether or not `prev_page_idx` and `page_idx` are both zero.
    pub is_page_idxes_zero: IsZeroOperation<T>,

    /// A witness to assert whether or not the index is zero.
    pub is_index_zero: IsZeroOperation<T>,
}

pub(crate) const NUM_PAGE_PROT_INIT_COLS: usize = size_of::<PageProtInitCols<u8>>();

impl<AB> Air<AB> for PageProtGlobalChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PageProtInitCols<AB::Var> = (*local).borrow();

        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(local.is_real);

        // Constrain that `local.is_real` is boolean.
        builder.assert_bool(local.is_real);
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::one(),
        );

        // Constrain that the page prot is just 3 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.page_prot.into(),
            AB::Expr::from_canonical_u8(3),
            AB::Expr::zero(),
            local.is_real,
        );

        // Constrain that the previous page index is valid.  The first limb is 4 bits, and the
        // other two limbs are 16 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.prev_page_idx[0].into(),
            AB::Expr::from_canonical_u8(4),
            AB::Expr::zero(),
            local.is_real,
        );
        builder.slice_range_check_u16(
            &[local.prev_page_idx[1].into(), local.prev_page_idx[2].into()],
            local.is_real,
        );

        // Constrain that the page index is valid.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.page_idx[0].into(),
            AB::Expr::from_canonical_u8(4),
            AB::Expr::zero(),
            local.is_real,
        );
        builder.slice_range_check_u16(
            &[local.page_idx[1].into(), local.page_idx[2].into()],
            local.is_real,
        );

        let interaction_kind = match self.kind {
            MemoryChipType::Initialize => InteractionKind::PageProtGlobalInitControl,
            MemoryChipType::Finalize => InteractionKind::PageProtGlobalFinalizeControl,
        };

        // Receive the previous index, page index, and validity state.
        builder.receive(
            AirInteraction::new(
                vec![local.index]
                    .into_iter()
                    .chain(local.prev_page_idx)
                    .chain(once(local.prev_valid))
                    .map(Into::into)
                    .collect(),
                local.is_real.into(),
                interaction_kind,
            ),
            InteractionScope::Local,
        );

        // Send the next index, page index, and validity state.
        builder.send(
            AirInteraction::new(
                vec![local.index + AB::Expr::one()]
                    .into_iter()
                    .chain(local.page_idx.map(Into::into))
                    .chain(once(local.is_comp.into()))
                    .collect(),
                local.is_real.into(),
                interaction_kind,
            ),
            InteractionScope::Local,
        );

        if self.kind == MemoryChipType::Initialize {
            // Send the "send interaction" to the global table.
            builder.send(
                AirInteraction::new(
                    vec![
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                        local.page_idx[0].into(),
                        local.page_idx[1].into(),
                        local.page_idx[2].into(),
                        local.page_prot.into(),
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
        } else {
            // Send the "receive interaction" to the global table.
            builder.send(
                AirInteraction::new(
                    vec![
                        local.clk_high.into(),
                        local.clk_low.into(),
                        local.page_idx[0].into(),
                        local.page_idx[1].into(),
                        local.page_idx[2].into(),
                        local.page_prot.into(),
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
        }

        // If it's the initialize chip, then assert that the page prot is the default page prot.
        if self.kind == MemoryChipType::Initialize {
            builder
                .when(local.is_real)
                .assert_eq(local.page_prot, AB::Expr::from_canonical_u8(DEFAULT_PAGE_PROT));
        }

        // Assert `prev_page_idx < page_idx` except the case `prev_page_idx = page_idx = index = 0`.
        // First, check if `prev_page_idx = page_idx = 0`, and check if `index = 0`.
        // SAFETY: Since `prev_page_idx` and `page_idx` are composed of valid (u4, u16, u16) limbs,
        // adding them to check if all limbs are zero is safe, as overflows are impossible.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                local.prev_page_idx[0]
                    + local.prev_page_idx[1]
                    + local.prev_page_idx[2]
                    + local.page_idx[0]
                    + local.page_idx[1]
                    + local.page_idx[2],
                local.is_page_idxes_zero,
                local.is_real.into(),
            ),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                local.index.into(),
                local.is_index_zero,
                local.is_real.into(),
            ),
        );

        // Comparison will be done unless `prev_page_idx = 0`, `page_idx = 0`, and `index = 0`.
        // If `is_real = 0`, then `is_comp` is zero.
        // If `is_real = 1`, then `is_comp` is zero when `prev_page_idx = page_idx = index = 0`.
        // If `is_real = 1`, then `is_comp` is equal to one otherwise.
        builder.assert_eq(
            local.is_comp,
            local.is_real
                * (AB::Expr::one() - local.is_page_idxes_zero.result * local.is_index_zero.result),
        );
        builder.assert_bool(local.is_comp);

        // The prev_page_idx[0] and page_idx[0] values need to be shifted by 12 bits, since they are
        // 4 bits and the LtOperationUnsigned operation will expect the words to be 16 bit limbs.
        <LtOperationUnsigned<AB::F> as SP1Operation<AB>>::eval(
            builder,
            LtOperationUnsignedInput::<AB>::new(
                Word([
                    local.prev_page_idx[0].into() * AB::Expr::from_canonical_u16(1 << 12),
                    local.prev_page_idx[1].into(),
                    local.prev_page_idx[2].into(),
                    AB::Expr::zero(),
                ]),
                Word([
                    local.page_idx[0].into() * AB::Expr::from_canonical_u16(1 << 12),
                    local.page_idx[1].into(),
                    local.page_idx[2].into(),
                    AB::Expr::zero(),
                ]),
                local.lt_cols,
                local.is_comp.into(),
            ),
        );
        builder.when(local.is_comp).assert_one(local.lt_cols.u16_compare_operation.bit);
    }
}

// #[cfg(test)]
// mod tests {
//     #![allow(clippy::print_stdout)]

//     use super::*;
//     use crate::programs::tests::*;
//     use crate::{
//         riscv::RiscvAir, syscall::precompiles::sha256::extend_tests::sha_extend_program,
//         utils::setup_logger,
//     };
//     use slop_baby_bear::BabyBear;
//     use sp1_core_executor::{Executor, Trace};
//     use sp1_stark::InteractionKind;
//     use sp1_stark::{
//         baby_bear_poseidon2::BabyBearPoseidon2, debug_interactions_with_all_chips, SP1CoreOpts,
//         StarkMachine,
//     };

//     #[test]
//     fn test_memory_generate_trace() {
//         let program = simple_program();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let shard = runtime.record.clone();

//         let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipType::Initialize);

//         let trace: RowMajorMatrix<BabyBear> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values);

//         let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipType::Finalize);
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
//         debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
//             &machine,
//             &pkey,
//             &shards.into_iter().map(|r| *r).collect::<Vec<_>>(),
//             vec![InteractionKind::Byte],
//             InteractionScope::Global,
//         );
//     }
// }
