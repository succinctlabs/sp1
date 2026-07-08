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
        // Byte-lookup half: the sorted-neighbor address-comparison and value range
        // checks. Kept separate from the global half so a prover that produces these
        // lookups elsewhere (fused into the device tracegen kernel) can run
        // `generate_global_dependencies` alone.
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
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

        MachineAir::<F>::generate_global_dependencies(self, input, output);
    }

    fn generate_global_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };

        let is_receive = match self.kind {
            MemoryChipType::Initialize => false,
            MemoryChipType::Finalize => true,
        };

        // The public-value event counters belong to the global half: they count the
        // global interactions this chip contributes.
        match self.kind {
            MemoryChipType::Initialize => {
                output.public_values.global_init_count += memory_events.len() as u32;
            }
            MemoryChipType::Finalize => {
                output.public_values.global_finalize_count += memory_events.len() as u32;
            }
        };

        memory_events.sort_by_key(|event| event.addr);

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

#[derive(AlignedBorrow, Default, Clone, Copy, StructReflection)]
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

pub const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> MemoryInitCols<T> {
    /// Backend-agnostic witgen for one `MemoryGlobalInit`/`MemoryGlobalFinalize`
    /// row. The chip's host tracegen has a sort + sequential-neighbor pass; the
    /// DEVICE port moves that to PACKING: events are sorted host-side and each row
    /// receives its own `prev_addr` (previous sorted event's address, or the shard
    /// public value for row 0) and `index` as inputs, making rows independent.
    ///
    /// `is_comp = (prev_addr != 0 || index != 0)` and `prev_valid` are recomputed
    /// in-DAG. On non-comparison rows the `lt_cols` gadget runs on zero-masked
    /// inputs (which yields the all-zero default columns the host writes) with its
    /// lookups guarded on `is_comp`.
    ///
    /// NOTE: `generate_dependencies` ALSO emits `GlobalInteractionEvent`s and bumps
    /// `public_values.global_*_count` — NOT modeled here; the device dependency
    /// path must stay off for this chip (host `generate_dependencies` still runs).
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut MemoryInitCols<WB::Field>,
        addr: WB::Nat,
        value: WB::Nat,
        timestamp: WB::Nat,
        prev_addr: WB::Nat,
        index: WB::Nat,
    ) {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);

        let clk_high = wb.bits(timestamp, 24, 32);
        cols.clk_high = wb.nat_to_field(clk_high);
        let clk_low = wb.bits(timestamp, 0, 24);
        cols.clk_low = wb.nat_to_field(clk_low);
        cols.index = wb.nat_to_field(index);

        // Address limbs (+ dependency u16 checks on limbs 0..3 of both addresses).
        let pa0 = wb.bits(prev_addr, 0, 16);
        let pa1 = wb.bits(prev_addr, 16, 16);
        let pa2 = wb.bits(prev_addr, 32, 16);
        for (i, limb) in [pa0, pa1, pa2].into_iter().enumerate() {
            wb.add_u16_range_check(limb);
            cols.prev_addr[i] = wb.nat_to_field(limb);
        }
        for i in 0..3 {
            let limb = wb.bits(addr, 16 * i as u32, 16);
            wb.add_u16_range_check(limb);
            cols.addr[i] = wb.nat_to_field(limb);
        }

        // Value limbs + the 8-bit split of the third limb (+ dependency checks).
        for i in 0..4 {
            let limb = wb.bits(value, 16 * i as u32, 16);
            wb.add_u16_range_check(limb);
            cols.value.0[i] = wb.nat_to_field(limb);
        }
        let vb0 = wb.bits(value, 32, 8);
        let vb1 = wb.bits(value, 40, 8);
        wb.add_u8_range_check(vb0, vb1);
        cols.value_lower = wb.nat_to_field(vb0);
        cols.value_upper = wb.nat_to_field(vb1);
        cols.is_real = wb.nat_to_field(one);

        // is_comp = (prev_addr != 0 || index != 0); prev_valid = (prev_addr != 0)
        // || (index == 0)  [host: 0 only when prev_addr == 0 && index != 0].
        let pa_zero = wb.eq(prev_addr, zero);
        let idx_zero = wb.eq(index, zero);
        let both_zero = wb.select(pa_zero, idx_zero, zero);
        let is_comp = wb.eq(both_zero, zero);
        cols.is_comp = wb.nat_to_field(is_comp);
        let prev_valid = wb.select(pa_zero, idx_zero, one);
        cols.prev_valid = wb.nat_to_field(prev_valid);

        // IsZero witnesses: prev_addr limb sum (< 3·2^16, no overflow) and index.
        let pa01 = wb.wrapping_add(pa0, pa1);
        let pa_sum = wb.wrapping_add(pa01, pa2);
        crate::operations::IsZeroOperation::<WB::Field>::witgen(
            wb,
            &mut cols.is_prev_addr_zero,
            pa_sum,
        );
        crate::operations::IsZeroOperation::<WB::Field>::witgen(wb, &mut cols.is_index_zero, index);

        // lt_cols: `1 = (prev_addr < addr)` on comparison rows; the all-zero default
        // otherwise — zero-masked inputs reproduce the default exactly (flags,
        // comparison limbs, not_eq_inv and bit all become 0) — with the gadget's
        // lookups guarded on `is_comp`.
        let pa_m = wb.select(is_comp, prev_addr, zero);
        let addr_m = wb.select(is_comp, addr, zero);
        let a_m = is_comp;
        wb.push_guard(is_comp);
        crate::operations::LtOperationUnsigned::<WB::Field>::witgen(
            wb,
            &mut cols.lt_cols,
            a_m,
            pa_m,
            addr_m,
        );
        wb.pop_guard();
    }
}

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

#[cfg(test)]
mod split_tests {
    use sp1_core_executor::{events::MemoryInitializeFinalizeEvent, ExecutionRecord};
    use sp1_hypercube::air::MachineAir;
    use sp1_primitives::SP1Field;

    use super::{MemoryChipType, MemoryGlobalChip};

    /// `generate_global_dependencies` must be exactly the global subset of
    /// `generate_dependencies`: same global events in the same (sorted) order, same
    /// public-value counter bumps, and no byte lookups — the contract the device
    /// prover relies on when it fuses this chip's byte lookups into the tracegen
    /// kernel and keeps only the globals on host.
    #[test]
    fn global_dependencies_are_the_global_subset() {
        for kind in [MemoryChipType::Initialize, MemoryChipType::Finalize] {
            let events: Vec<MemoryInitializeFinalizeEvent> = (0..100u64)
                .map(|i| MemoryInitializeFinalizeEvent {
                    // Deliberately unsorted addresses so the sort matters.
                    addr: (i * 37) % 100 * 8 + 0x2000,
                    value: i.wrapping_mul(0x0123_4567_89AB_CDEF),
                    timestamp: i + 1,
                })
                .collect();
            let shard = match kind {
                MemoryChipType::Initialize => ExecutionRecord {
                    global_memory_initialize_events: events,
                    ..Default::default()
                },
                MemoryChipType::Finalize => {
                    ExecutionRecord { global_memory_finalize_events: events, ..Default::default() }
                }
            };
            let chip = MemoryGlobalChip::new(kind);

            let mut full = ExecutionRecord::default();
            MachineAir::<SP1Field>::generate_dependencies(&chip, &shard, &mut full);
            let mut globals_only = ExecutionRecord::default();
            MachineAir::<SP1Field>::generate_global_dependencies(&chip, &shard, &mut globals_only);

            assert_eq!(globals_only.global_interaction_events, full.global_interaction_events);
            assert!(!full.global_interaction_events.is_empty());
            assert_eq!(
                globals_only.public_values.global_init_count,
                full.public_values.global_init_count
            );
            assert_eq!(
                globals_only.public_values.global_finalize_count,
                full.public_values.global_finalize_count
            );
            assert!(globals_only.byte_lookups.is_empty());
            assert!(!full.byte_lookups.is_empty());
        }
    }
}
