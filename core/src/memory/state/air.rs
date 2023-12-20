use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;

use crate::air::{Bool, CurtaAirBuilder, Word};
use p3_field::AbstractField;

use valida_derive::AlignedBorrow;

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
}

// impl<T> MemoryStateAir<T> {
//     pub fn eval<AB: CurtaAirBuilder>(&self, builder: &mut AB)
//     where
//         T: Into<AB::Expr> + Copy,
//     {
//         builder.send_memory(
//             self.clk,
//             self.addr,
//             self.value,
//             self.is_read.0,
//             AB::F::one(),
//         );
//     }
// }
