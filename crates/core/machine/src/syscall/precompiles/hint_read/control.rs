use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, PrecompileEvent},
    ByteOpcode, ExecutionRecord, Program, SyscallCode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind,
};
use sp1_primitives::consts::u64_to_u16_limbs;

use crate::{air::SP1CoreAirBuilder, utils::next_multiple_of_32};

/// The columns of the [`HintReadControlChip`]. One row per `HINT_READ` syscall.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct HintReadControlCols<T> {
    /// The high 24 bits of the clk.
    pub clk_high: T,

    /// The low 24 bits of the clk.
    pub clk_low: T,

    /// The pointer the hint is written to, as 3 u16 limbs.
    pub ptr: [T; 3],

    /// The number of bytes requested by the hint.
    pub len_bytes: T,

    /// The number of words written (`len_bytes.div_ceil(8)`). Derived, not constrained here.
    pub num_words: T,

    /// Whether this row is real or padding.
    pub is_real: T,
}

/// The number of columns in the [`HintReadControlChip`].
pub const NUM_HINT_READ_CONTROL_COLS: usize = size_of::<HintReadControlCols<u8>>();

/// The hint-read controller chip: receives the `HINT_READ` syscall and drives the per-word
/// [`HintReadChip`] state machine.
#[derive(Default)]
pub struct HintReadControlChip;

impl HintReadControlChip {
    /// Create a new [`HintReadControlChip`].
    pub const fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for HintReadControlChip {
    fn width(&self) -> usize {
        NUM_HINT_READ_CONTROL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for HintReadControlChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "HintReadControl"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::HINT_READ).len();
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
        let events = input.get_precompile_events(SyscallCode::HINT_READ);

        unsafe {
            core::ptr::write_bytes(buffer.as_mut_ptr(), 0, padded_nb_rows * width);
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        for (row, (_, event)) in values.chunks_exact_mut(width).zip(events.iter()) {
            let PrecompileEvent::HintRead(event) = event else { unreachable!() };
            let cols: &mut HintReadControlCols<F> = row.borrow_mut();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.ptr = u64_to_u16_limbs(event.ptr)[..3]
                .iter()
                .map(|&l| F::from_canonical_u16(l))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            cols.len_bytes = F::from_canonical_u64(event.len_bytes);
            cols.num_words = F::from_canonical_u64(event.len_bytes.div_ceil(8));
            cols.is_real = F::one();
        }
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        for (_, event) in input.get_precompile_events(SyscallCode::HINT_READ).iter() {
            let PrecompileEvent::HintRead(event) = event else { unreachable!() };
            let slack = (8 * event.len_bytes.div_ceil(8) - event.len_bytes) as u16;
            output.add_bit_range_check(slack, 3);
            output.add_bit_range_check(event.len_bytes.div_ceil(8) as u16, 16);
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

impl<AB> Air<AB> for HintReadControlChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &HintReadControlCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // Receive the syscall, matching the send from `SyscallInstrsChip`.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::HINT_READ.syscall_id()),
            AB::Expr::zero(),
            local.ptr.map(Into::into),
            [local.len_bytes.into(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        // The state-machine message is `[clk_high, clk_low, ptr (3 limbs), index]`.
        // Send the initial state (index = 0) into the per-word state machine.
        builder.send(
            AirInteraction::new(
                vec![
                    local.clk_high.into(),
                    local.clk_low.into(),
                    local.ptr[0].into(),
                    local.ptr[1].into(),
                    local.ptr[2].into(),
                    AB::Expr::zero(),
                ],
                local.is_real.into(),
                InteractionKind::HintRead,
            ),
            InteractionScope::Local,
        );

        // Receive the final state (index = num_words) back from the state machine.
        builder.receive(
            AirInteraction::new(
                vec![
                    local.clk_high.into(),
                    local.clk_low.into(),
                    local.ptr[0].into(),
                    local.ptr[1].into(),
                    local.ptr[2].into(),
                    local.num_words.into(),
                ],
                local.is_real.into(),
                InteractionKind::HintRead,
            ),
            InteractionScope::Local,
        );

        // Check `num_words` is a valid `u16`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.num_words.into(),
            AB::Expr::from_canonical_u32(16),
            AB::Expr::zero(),
            local.is_real,
        );

        // Check `num_words == ceil(len_bytes / 8)` by `0 <= 8 * num_words - len_bytes < 8`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.num_words.into() * AB::Expr::from_canonical_u32(8) - local.len_bytes.into(),
            AB::Expr::from_canonical_u32(3),
            AB::Expr::zero(),
            local.is_real,
        );
    }
}
