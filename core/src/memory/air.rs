use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;
use core::mem::transmute;

use p3_air::Air;
use p3_air::{AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::{Field, PrimeField32};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;

use valida_derive::AlignedBorrow;

use crate::air::reduce;

use crate::air::CurtaAirBuilder;
use crate::air::{Bool, Word};

use super::MemoryChip;

pub const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();
pub const MEM_COL: MemoryCols<usize> = make_col_map();

/// An AIR table for memory accesses.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct MemoryCols<T> {
    /// The clock cycle value for this memory access.
    pub clk: T,
    /// The address of the memory access.
    pub addr: Word<T>,
    /// The value being read from or written to memory.
    pub value: Word<T>,
    /// Whether the memory is being read from or written to.
    pub is_read: Bool<T>,
    /// The multiplicity of this memory access.
    pub multiplicity: T,

    /// The previous address of the table. Needed for the bus argument access of "less_than"
    pub prev_addr: Word<T>,
    /// A decoding of the clk to a 32-bit word.
    pub clk_word: Word<T>,
    /// The next clk_word of the table. Needed for the bus argument access of "less_than".
    pub prev_clk_word: Word<T>,
    /// A flag indicating whether the address is equal to the previous address.
    pub is_addr_eq: Bool<T>,
    /// A flag indicating whether the address is strictly increasing.
    pub is_addr_lt: Bool<T>,
    /// A flag indicating whether the clock cycle is equal to the previous clock cycle.
    pub is_clk_eq: Bool<T>,
    /// A flag indicating whether the clock cycle is strictly increasing.
    pub is_clk_lt: Bool<T>,
    /// A flag to indicate whether the memory access consistency is checked.
    pub is_checked: Bool<T>,
}

const fn make_col_map() -> MemoryCols<usize> {
    let indices_arr = indices_arr::<NUM_MEMORY_COLS>();
    unsafe { transmute::<[usize; NUM_MEMORY_COLS], MemoryCols<usize>>(indices_arr) }
}

impl MemoryCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_MEMORY_COLS] = row
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        unsafe { transmute::<[u32; NUM_MEMORY_COLS], MemoryCols<u32>>(sized) }
    }
}

impl<F: Field> BaseAir<F> for MemoryChip {
    fn width(&self) -> usize {
        NUM_MEMORY_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for MemoryChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryCols<AB::Var> = main.row_slice(0).borrow();
        let next: &MemoryCols<AB::Var> = main.row_slice(1).borrow();

        // dummy constraint
        builder.assert_zero(local.clk * local.clk * local.clk - local.clk * local.clk * local.clk);

        // Memory consistency checks
        //
        // Memory consistency assertion. When the is_checked flag is set, the value should not
        // change between the local and next row.
        for (val, val_next) in local.value.into_iter().zip(next.value) {
            builder
                .when_transition()
                .when(next.is_checked.0)
                .assert_zero(val - val_next);
        }
        // Assert that `is_checked` is determined by whether the address is not changing and having
        // a read operation.
        builder
            .when_transition()
            .assert_eq(next.is_checked.0, next.is_read.0 * next.is_addr_eq.0);
        // Assert that when the current instruction is a write, we must have a change in either the
        // address or the clock cycle.
        builder
            .when_transition()
            .when(local.is_read.0 - AB::F::one())
            .assert_zero(next.is_addr_eq.0 * next.is_clk_eq.0);
        // Assert that `clk_word` is a decoding of `clk`.
        let clk_expected = reduce::<AB>(local.clk_word);
        builder.assert_eq(clk_expected, local.clk);
        // If the operation is a write, the multiplicity must be 1.
        // TODO: Figure out if this constraint is necessary.
        // builder.assert_zero(local.is_read.0 * (local.multiplicity - AB::F::one()));

        // Lookup values validity checks
        //
        // Assert that the next address is equal to the next row address.
        builder
            .when_transition()
            .assert_word_eq(local.addr, next.prev_addr);

        // Assert the the prev clock cycle word is equal to the row clock cycle word of the last row.
        builder
            .when_transition()
            .assert_word_eq(local.clk_word, next.prev_clk_word);

        // Validity checks on the boolean flags.
        //
        // The booleans `is_addr_lt` and `is_clk_lt` are obtained via a lookup into a table of STLU
        // operations. This means they are assumed to be boolean, and that `is_addr_lt` is set to
        // `next_addr < addr` and `is_clk_lt` is set to `next_clk_word < clk_word`. We can use
        // these assumptions when constraining the equality flags below.

        // Constrain untrusted booleans to be either 0 or 1.
        builder.assert_is_bool(local.is_read);
        builder.assert_is_bool(local.is_addr_eq);
        builder.assert_is_bool(local.is_clk_eq);

        // Constrain address to be non-decreasing and the validity of `is_addr_eq`.
        //
        // Constrain `is_addr_eq` to be 1 if the address is equal to the previous address and equals
        // to zero when the address is not equal to the previous address. For this constraint to
        // hold, we will ensure the following sufficient conditions:
        //    - `is_addr_eq` and `is_addr_lt` are disjoint and `is_addr_lt || is_addr_eq` is true .
        //       This is done by asserting that `is_addr_eq + is_addr_lt = 1`.
        //    - `is_addr_eq` is `1` when the address is equal to the previous address. This verifies
        //       that whenever `is_addr_lt` is `0`, we have an equality.
        builder
            .when_transition()
            .assert_one(next.is_addr_eq.0 + next.is_addr_lt.0);
        builder.assert_bool(local.is_addr_eq.0);
        builder
            .when_transition()
            .when(next.is_addr_eq.0)
            .assert_word_eq(local.addr, next.addr);

        // Assert that when the address remains the same, the value of the clock cycle is
        // non-decreasing, and the validity of `is_clk_eq`. We will use checks analogous to the ones
        // above for address, filtered by the condition that the address is equal to the previous
        // address.
        builder
            .when_transition()
            .when(next.is_addr_eq.0)
            .assert_one(next.is_clk_lt.0 + next.is_clk_eq.0);
        // For the assertion that when `is_clk_eq` is one when the clock cycle is equal to the previous
        // one, we do not filter by the address condition to preserve the degree of the constraint.
        builder
            .when_transition()
            .when(next.is_clk_eq.0)
            .assert_eq(next.clk, local.clk);

        // builder.recieve_memory(
        //     local.clk,
        //     local.addr,
        //     local.value,
        //     local.is_read.0,
        //     local.multiplicity,
        // );
    }
}
