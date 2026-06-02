use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind, Word,
};
use sp1_primitives::consts::u64_to_u16_limbs;

use crate::{
    air::SP1CoreAirBuilder, memory::MemoryAccessCols, operations::AddrAddOperation,
    utils::next_multiple_of_32,
};

/// The columns of the [`HintReadChip`]. One row per written word.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct HintReadCols<T> {
    /// The high 24 bits of the clk.
    pub clk_high: T,

    /// The low 24 bits of the clk.
    pub clk_low: T,

    /// The base pointer of the hint, as 3 u16 limbs.
    pub ptr: [T; 3],

    /// The index of the word being written within this hint.
    pub index: T,

    /// The write address `ptr + 8 * index`. Computed, not constrained here.
    pub addr: AddrAddOperation<T>,

    /// The value written to memory.
    pub value: Word<T>,

    /// The memory write access.
    pub memory_access: MemoryAccessCols<T>,

    /// Whether this row is real or padding.
    pub is_real: T,
}

/// The number of columns in the [`HintReadChip`].
pub const NUM_HINT_READ_COLS: usize = size_of::<HintReadCols<u8>>();

/// The hint-read chip: each row performs one word's arbitrary write at `ptr + 8 * index`, and
/// advances the state machine index.
#[derive(Default)]
pub struct HintReadChip;

impl HintReadChip {
    /// Create a new [`HintReadChip`].
    pub const fn new() -> Self {
        Self
    }

    /// Flatten the `HINT_READ` events into one `(clk, ptr, index, record)` unit per written word.
    fn word_units(
        input: &ExecutionRecord,
    ) -> Vec<(u64, u64, usize, sp1_core_executor::events::MemoryWriteRecord)> {
        let mut units = Vec::new();
        for (_, event) in input.get_precompile_events(SyscallCode::HINT_READ).iter() {
            let PrecompileEvent::HintRead(event) = event else { unreachable!() };
            for (i, record) in event.memory_records.iter().enumerate() {
                units.push((event.clk, event.ptr, i, *record));
            }
        }
        units
    }
}

impl<F> BaseAir<F> for HintReadChip {
    fn width(&self) -> usize {
        NUM_HINT_READ_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for HintReadChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "HintRead"
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let width = <Self as BaseAir<F>>::width(self);
        for (_, ptr, index, record) in Self::word_units(input) {
            let mut row = vec![F::zero(); width];
            let cols: &mut HintReadCols<F> = row.as_mut_slice().borrow_mut();
            cols.addr.populate(output, ptr, 8 * index as u64);
            cols.memory_access.populate(MemoryRecordEnum::Write(record), output);
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input
            .get_precompile_events(SyscallCode::HINT_READ)
            .iter()
            .map(|(_, event)| {
                let PrecompileEvent::HintRead(event) = event else { unreachable!() };
                event.memory_records.len()
            })
            .sum();
        let size_log2 = input.fixed_log2_rows::<F, Self>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let width = <Self as BaseAir<F>>::width(self);
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let units = Self::word_units(input);

        unsafe {
            core::ptr::write_bytes(buffer.as_mut_ptr(), 0, padded_nb_rows * width);
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        for (row, (clk, ptr, index, record)) in values.chunks_exact_mut(width).zip(units) {
            let cols: &mut HintReadCols<F> = row.borrow_mut();
            let mut blu = Vec::new();
            cols.clk_high = F::from_canonical_u32((clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((clk & 0xFFFFFF) as u32);
            cols.ptr = u64_to_u16_limbs(ptr)[..3]
                .iter()
                .map(|&l| F::from_canonical_u16(l))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            cols.index = F::from_canonical_usize(index);
            cols.addr.populate(&mut blu, ptr, 8 * index as u64);
            cols.value = Word::from(record.value);
            cols.memory_access.populate(MemoryRecordEnum::Write(record), &mut blu);
            cols.is_real = F::one();
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::HINT_READ).is_empty()
        }
    }
}

impl<AB> Air<AB> for HintReadChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &HintReadCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // The state-machine message is `[clk_high, clk_low, ptr (3 limbs), index]`.
        // Receive the current state (index) and send the next state (index + 1).
        builder.receive(
            AirInteraction::new(
                vec![
                    local.clk_high.into(),
                    local.clk_low.into(),
                    local.ptr[0].into(),
                    local.ptr[1].into(),
                    local.ptr[2].into(),
                    local.index.into(),
                ],
                local.is_real.into(),
                InteractionKind::HintRead,
            ),
            InteractionScope::Local,
        );
        builder.send(
            AirInteraction::new(
                vec![
                    local.clk_high.into(),
                    local.clk_low.into(),
                    local.ptr[0].into(),
                    local.ptr[1].into(),
                    local.ptr[2].into(),
                    local.index + AB::Expr::one(),
                ],
                local.is_real.into(),
                InteractionKind::HintRead,
            ),
            InteractionScope::Local,
        );

        // addr = ptr + 8 * index.
        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([local.ptr[0].into(), local.ptr[1].into(), local.ptr[2].into(), AB::Expr::zero()]),
            Word([
                local.index.into() * AB::Expr::from_canonical_u32(8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.addr,
            local.is_real.into(),
        );

        // Write the value to memory at the computed address.
        builder.eval_memory_access_write(
            local.clk_high,
            local.clk_low,
            &local.addr.value.map(Into::into),
            local.memory_access,
            local.value,
            local.is_real,
        );
    }
}
