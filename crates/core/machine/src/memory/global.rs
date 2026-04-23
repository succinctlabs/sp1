use super::MemoryChipType;
use crate::{
    air::{SP1CoreAirBuilder, SP1Operation, WordAirBuilder},
    operations::{
        IsZeroOperation, IsZeroOperationInput, LtOperationUnsigned, LtOperationUnsignedInput,
    },
    utils::next_multiple_of_32,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator, ParallelSlice,
    ParallelSliceMut,
};
use sp1_core_executor::{
    events::{ByteRecord, GlobalInteractionEvent, MemoryInitializeFinalizeEvent},
    ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind, Word,
};
use sp1_primitives::consts::u64_to_u16_limbs;
use std::iter::once;
use struct_reflection::{StructReflection, StructReflectionHelper};

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryGlobalChip {
    pub kind: MemoryChipType,
}

impl MemoryGlobalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }
}

impl<F> BaseAir<F> for MemoryGlobalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryGlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        match self.kind {
            MemoryChipType::Initialize => "MemoryGlobalInit",
            MemoryChipType::Finalize => "MemoryGlobalFinalize",
        }
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };

        let is_receive = match self.kind {
            MemoryChipType::Initialize => false,
            MemoryChipType::Finalize => true,
        };

        match self.kind {
            MemoryChipType::Initialize => {
                output.public_values.global_init_count += memory_events.len() as u32;
            }
            MemoryChipType::Finalize => {
                output.public_values.global_finalize_count += memory_events.len() as u32;
            }
        };

        let previous_addr = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr,
        };

        memory_events.sort_by_key(|event| event.addr);

        let chunk_size = std::cmp::max(memory_events.len() / num_cpus::get(), 1);
        let indices = (0..memory_events.len()).collect::<Vec<_>>();
        let blu_batches = indices
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut blu = Vec::new();
                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                chunk.iter().for_each(|&i| {
                    let addr = memory_events[i].addr;
                    let value = memory_events[i].value;
                    let prev_addr = if i == 0 { previous_addr } else { memory_events[i - 1].addr };
                    blu.add_u16_range_checks(&u64_to_u16_limbs(value));
                    blu.add_u16_range_checks(&u64_to_u16_limbs(prev_addr)[0..3]);
                    blu.add_u16_range_checks(&u64_to_u16_limbs(addr)[0..3]);
                    let value_lower = (value >> 32 & 0xFF) as u8;
                    let value_upper = (value >> 40 & 0xFF) as u8;
                    blu.add_u8_range_check(value_lower, value_upper);
                    if i != 0 || prev_addr != 0 {
                        cols.lt_cols.populate_unsigned(&mut blu, 1, prev_addr, addr);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();
        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());

        let events = memory_events.into_iter().map(|event| {
            let interaction_clk_high = if is_receive { (event.timestamp >> 24) as u32 } else { 0 };
            let interaction_clk_low =
                if is_receive { (event.timestamp & 0xFFFFFF) as u32 } else { 0 };
            let limb_1 =
                (event.value & 0xFFFF) as u32 + (1 << 16) * (event.value >> 32 & 0xFF) as u32;
            let limb_2 =
                (event.value >> 16 & 0xFFFF) as u32 + (1 << 16) * (event.value >> 40 & 0xFF) as u32;

            GlobalInteractionEvent {
                message: [
                    interaction_clk_high,
                    interaction_clk_low,
                    (event.addr & 0xFFFF) as u32,
                    ((event.addr >> 16) & 0xFFFF) as u32,
                    ((event.addr >> 32) & 0xFFFF) as u32,
                    limb_1,
                    limb_2,
                    ((event.value >> 48) & 0xFFFF) as u32,
                ],
                is_receive,
                kind: InteractionKind::Memory as u8,
            }
        });
        output.global_interaction_events.extend(events);
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = match self.kind {
            MemoryChipType::Initialize => &input.global_memory_initialize_events,
            MemoryChipType::Finalize => &input.global_memory_finalize_events,
        };
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
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };

        let previous_addr = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr,
        };

        memory_events.sort_by_key(|event| event.addr);

        let padded_nb_rows = <MemoryGlobalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = memory_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_MEMORY_INIT_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_MEMORY_INIT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_MEMORY_INIT_COLS)
        };

        values.par_chunks_exact_mut(NUM_MEMORY_INIT_COLS).zip(memory_events.par_iter()).for_each(
            |(row, event)| {
                let cols: &mut MemoryInitCols<F> = row.borrow_mut();
                let MemoryInitializeFinalizeEvent { addr, value, timestamp } = event.to_owned();

                cols.addr[0] = F::from_canonical_u16((addr & 0xFFFF) as u16);
                cols.addr[1] = F::from_canonical_u16(((addr >> 16) & 0xFFFF) as u16);
                cols.addr[2] = F::from_canonical_u16(((addr >> 32) & 0xFFFF) as u16);
                cols.clk_high = F::from_canonical_u32((timestamp >> 24) as u32);
                cols.clk_low = F::from_canonical_u32((timestamp & 0xFFFFFF) as u32);
                cols.value = Word::from(value);
                cols.is_real = F::one();
                cols.value_lower = F::from_canonical_u32((value >> 32 & 0xFF) as u32);
                cols.value_upper = F::from_canonical_u32((value >> 40 & 0xFF) as u32);
            },
        );

        let mut blu = vec![];
        for i in 0..memory_events.len() {
            let row_start = i * NUM_MEMORY_INIT_COLS;
            let row = &mut values[row_start..row_start + NUM_MEMORY_INIT_COLS];
            let cols: &mut MemoryInitCols<F> = row.borrow_mut();

            let addr = memory_events[i].addr;
            let prev_addr = if i == 0 { previous_addr } else { memory_events[i - 1].addr };

            if prev_addr == 0 && i != 0 {
                cols.prev_valid = F::zero();
            } else {
                cols.prev_valid = F::one();
            }
            cols.index = F::from_canonical_u32(i as u32);
            cols.prev_addr[0] = F::from_canonical_u16((prev_addr & 0xFFFF) as u16);
            cols.prev_addr[1] = F::from_canonical_u16(((prev_addr >> 16) & 0xFFFF) as u16);
            cols.prev_addr[2] = F::from_canonical_u16(((prev_addr >> 32) & 0xFFFF) as u16);
            cols.is_prev_addr_zero.populate_from_field_element(
                cols.prev_addr[0] + cols.prev_addr[1] + cols.prev_addr[2],
            );
            cols.is_index_zero.populate(i as u64);
            if prev_addr != 0 || i != 0 {
                cols.is_comp = F::one();
                cols.lt_cols.populate_unsigned(&mut blu, 1, prev_addr, addr);
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
                MemoryChipType::Initialize => !shard.global_memory_initialize_events.is_empty(),
                MemoryChipType::Finalize => !shard.global_memory_finalize_events.is_empty(),
            }
        }
    }

    fn column_names(&self) -> Vec<String> {
        MemoryInitCols::<F>::struct_reflection().unwrap()
    }
}

#[derive(AlignedBorrow, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct MemoryInitCols<T: Copy> {
    /// The top bits of the timestamp of the memory access.
    pub clk_high: T,

    /// The low bits of the timestamp of the memory access.
    pub clk_low: T,

    /// The index of the memory access.
    pub index: T,

    /// The address of the previous memory access.
    pub prev_addr: [T; 3],

    /// The address of the memory access.
    pub addr: [T; 3],

    /// Comparison assertions for address to be strictly increasing.
    pub lt_cols: LtOperationUnsigned<T>,

    /// The value of the memory access.
    pub value: Word<T>,

    /// Lower half of third limb of the value
    pub value_lower: T,

    /// Upper half of third limb of the value
    pub value_upper: T,

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether or not we are making the assertion `prev_addr < addr`.
    pub is_comp: T,

    /// The validity of previous state.
    /// The unique invalid state is when the chip only initializes address 0 once.
    pub prev_valid: T,

    /// A witness to assert whether or not `prev_addr` is zero.
    pub is_prev_addr_zero: IsZeroOperation<T>,

    /// A witness to assert whether or not the index is zero.
    pub is_index_zero: IsZeroOperation<T>,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<AB> Air<AB> for MemoryGlobalChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        // Constrain that `local.is_real` is boolean.
        builder.assert_bool(local.is_real);
        // Constrain that the value is a valid `Word`.
        builder.slice_range_check_u16(&local.value.0, local.is_real);
        // Constrain that the previous address is a valid `Word`.
        builder.slice_range_check_u16(&local.prev_addr, local.is_real);
        // Constrain that the address is a valid `Word`.
        builder.slice_range_check_u16(&local.addr, local.is_real);

        // Assert that value_lower and value_upper are the lower and upper halves of the third limb.
        builder.assert_eq(
            local.value.0[2],
            local.value_lower + local.value_upper * AB::F::from_canonical_u32(1 << 8),
        );
        builder.slice_range_check_u8(&[local.value_lower, local.value_upper], local.is_real);

        let interaction_kind = match self.kind {
            MemoryChipType::Initialize => InteractionKind::MemoryGlobalInitControl,
            MemoryChipType::Finalize => InteractionKind::MemoryGlobalFinalizeControl,
        };

        // Receive the previous index, address, and validity state.
        builder.receive(
            AirInteraction::new(
                vec![local.index]
                    .into_iter()
                    .chain(local.prev_addr)
                    .chain(once(local.prev_valid))
                    .map(Into::into)
                    .collect(),
                local.is_real.into(),
                interaction_kind,
            ),
            InteractionScope::Local,
        );

        // Send the next index, address, and validity state.
        builder.send(
            AirInteraction::new(
                vec![local.index + AB::Expr::one()]
                    .into_iter()
                    .chain(local.addr.map(Into::into))
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
                        local.addr[0].into(),
                        local.addr[1].into(),
                        local.addr[2].into(),
                        local.value.0[0] + local.value_lower * AB::F::from_canonical_u32(1 << 16),
                        local.value.0[1] + local.value_upper * AB::F::from_canonical_u32(1 << 16),
                        local.value.0[3].into(),
                        AB::Expr::one(),
                        AB::Expr::zero(),
                        AB::Expr::from_canonical_u8(InteractionKind::Memory as u8),
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
                        local.addr[0].into(),
                        local.addr[1].into(),
                        local.addr[2].into(),
                        local.value.0[0] + local.value_lower * AB::F::from_canonical_u32(1 << 16),
                        local.value.0[1] + local.value_upper * AB::F::from_canonical_u32(1 << 16),
                        local.value.0[3].into(),
                        AB::Expr::zero(),
                        AB::Expr::one(),
                        AB::Expr::from_canonical_u8(InteractionKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    InteractionKind::Global,
                ),
                InteractionScope::Local,
            );
        }

        // Assert that `prev_addr < addr` when `prev_addr != 0` or `index != 0`.
        // First, check if `prev_addr != 0`, and check if `index != 0`.
        // SAFETY: Since `prev_addr` are composed of valid u16 limbs, adding them to check if
        // all three limbs are zero is safe, as overflows are impossible.
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                local.prev_addr[0] + local.prev_addr[1] + local.prev_addr[2],
                local.is_prev_addr_zero,
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

        // Comparison will be done unless both `prev_addr == 0` and `index == 0`.
        // If `is_real = 0`, then `is_comp` will be zero.
        // If `is_real = 1`, then `is_comp` will be zero when `prev_addr == 0` and `index == 0`.
        // If `is_real = 1`, then `is_comp` will be one when `prev_addr != 0` or `index != 0`.
        builder.assert_eq(
            local.is_comp,
            local.is_real
                * (AB::Expr::one() - local.is_prev_addr_zero.result * local.is_index_zero.result),
        );
        builder.assert_bool(local.is_comp);

        // If `is_comp = 1`, then `prev_addr < addr` should hold.
        <LtOperationUnsigned<AB::F> as SP1Operation<AB>>::eval(
            builder,
            LtOperationUnsignedInput::<AB>::new(
                Word([
                    local.prev_addr[0].into(),
                    local.prev_addr[1].into(),
                    local.prev_addr[2].into(),
                    AB::Expr::zero(),
                ]),
                Word([
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    AB::Expr::zero(),
                ]),
                local.lt_cols,
                local.is_comp.into(),
            ),
        );
        builder.when(local.is_comp).assert_one(local.lt_cols.u16_compare_operation.bit);

        // If `prev_addr == 0` and `index == 0`, then `addr == 0`, and the `value` should be zero.
        // SAFETY: Since `local.addr` is valid u16 limbs, one can constrain that the sum of the
        // limbs is zero in order to constrain that `addr == 0`, as no overflow is possible.
        // This forces the initialization of address 0 with value 0.
        // Constraints related to register %x0: Register %x0 should always be 0.
        // See 2.6 Load and Store Instruction on P.18 of the RISC-V spec.
        let is_not_comp = local.is_real - local.is_comp;
        builder
            .when(is_not_comp.clone())
            .assert_zero(local.addr[0] + local.addr[1] + local.addr[2]);
        builder.when(is_not_comp.clone()).assert_word_zero(local.value);
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
//     use sp1_primitives::SP1Field;
//     use sp1_core_executor::{Executor, Trace};
//     use sp1_hypercube::InteractionKind;
//     use sp1_hypercube::{
//         koala_bear_poseidon2::SP1InnerPcs, debug_interactions_with_all_chips,
// SP1CoreOpts,         StarkMachine,
//     };

//     #[test]
//     fn test_memory_generate_trace() {
//         let program = simple_program();
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.run::<Trace>().unwrap();
//         let shard = runtime.record.clone();

//         let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipType::Initialize);

//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values);

//         let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipType::Finalize);
//         let trace: RowMajorMatrix<SP1Field> =
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
//         debug_interactions_with_all_chips::<SP1InnerPcs, RiscvAir<SP1Field>>(
//             &machine,
//             &pkey,
//             &shards.into_iter().map(|r| *r).collect::<Vec<_>>(),
//             vec![InteractionKind::Byte],
//             InteractionScope::Global,
//         );
//     }
// }
