use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;

use crate::air::{Bool, CurtaAirBuilder, Word};
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;

use p3_field::Field;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

use super::MemoryStateChip;

pub const NUM_MEMORY_STATE_COLS: usize = size_of::<MemoryStateCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct MemoryStateCols<T> {
    /// The clock cycle value for this memory access.
    pub clk: T,
    /// The address of the memory access.
    pub addr: Word<T>,
    /// The value being read from or written to memory.
    pub value: Word<T>,
    /// Whether the memory was being read from or written to.
    pub is_read: Bool<T>,

    pub is_real: Bool<T>,
}

impl<F: Field> BaseAir<F> for MemoryStateChip {
    fn width(&self) -> usize {
        NUM_MEMORY_STATE_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for MemoryStateChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryStateCols<AB::Var> = main.row_slice(0).borrow();

        let is_dummy = AB::Expr::one() - local.is_real.0;

        builder.assert_is_bool(local.is_real);

        // If the dummy flag is set, everything else should be set to zero.
        builder.when(is_dummy.clone()).assert_zero(local.clk);
        builder.when(is_dummy.clone()).assert_word_zero(local.addr);
        builder.when(is_dummy.clone()).assert_word_zero(local.value);
        builder.when(is_dummy).assert_is_bool(local.is_read);

        builder.send_memory(
            local.clk,
            local.addr,
            local.value,
            local.is_read.0,
            local.is_real.0,
        );
    }
}
