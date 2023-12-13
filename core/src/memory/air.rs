use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;
use core::mem::transmute;

use p3_air::VirtualPairCol;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;

use crate::air::reduce;
use crate::air::{AirVariable, Bool, Word};
use crate::lookup::Interaction;
use crate::memory::interaction::MemoryInteraction;

#[derive(Debug, Clone, Copy)]
pub struct MemoryAir;

const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();
const MEM_COL: MemoryCols<usize> = make_col_map();

/// An AIR table for memory accesses.
#[derive(Debug, Clone)]
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

    /// The next address of the table. Needed for the bus argument access of "less_than"
    pub next_addr: Word<T>,
    /// A decoding of the clk to a 32-bit word.
    pub clk_word: Word<T>,
    /// The next clk_word of the table. Needed for the bus argument access of "less_than".
    pub next_clk_word: Word<T>,
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

impl<T> Borrow<MemoryCols<T>> for [T] {
    fn borrow(&self) -> &MemoryCols<T> {
        // TODO: Double check if this is correct & consider making asserts debug-only.
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MemoryCols<T>>() };
        assert!(prefix.is_empty(), "Data was not aligned");
        assert!(suffix.is_empty(), "Data was not aligned");
        assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MemoryCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MemoryCols<T> {
        // TODO: Double check if this is correct & consider making asserts debug-only.
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MemoryCols<T>>() };
        assert!(prefix.is_empty(), "Data was not aligned");
        assert!(suffix.is_empty(), "Data was not aligned");
        assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<F: Field> BaseAir<F> for MemoryAir {
    fn width(&self) -> usize {
        NUM_MEMORY_COLS
    }
}

impl<AB: AirBuilder> Air<AB> for MemoryAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryCols<AB::Var> = main.row_slice(0).borrow();
        let next: &MemoryCols<AB::Var> = main.row_slice(1).borrow();

        // Memory consistency checks
        //
        // Memory consistency assertion. When the is_checked flag is set, the value should not
        // change between the local and next row.
        for (val, val_next) in local.value.into_iter().zip(next.value) {
            builder
                .when_transition()
                .when(local.is_checked.0)
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
            .when(local.is_read.0)
            .assert_one(next.is_addr_eq.0 + next.is_clk_lt.0);
        // Assert that `clk_word` is a decoding of `clk`.
        let clk_expected = reduce::<AB>(local.clk_word);
        builder.assert_eq(clk_expected, local.clk);
        // If the operation is a write, the multiplicity must be 1.
        builder
            .when(local.is_read.0)
            .assert_zero(local.multiplicity - AB::F::one());

        // Lookup values validity checks
        //
        // Assert that the next address is equal to the next row address.
        for (byte, byte_next) in local.next_addr.into_iter().zip(next.addr) {
            builder.when_transition().assert_eq(byte, byte_next);
        }
        // Assert the the next clock cycle word is equal to the next row clock cycle word.
        for (byte, byte_next) in local.next_clk_word.into_iter().zip(next.clk_word) {
            builder.when_transition().assert_eq(byte, byte_next);
        }

        // Validity checks on the boolean flags.
        //
        // The booleans `is_addr_lt` and `is_clk_lt` are obtained via a lookup into a table of STLU
        // operations. This means they are assumed to be boolean, and that `is_addr_lt` is set to
        // `next_addr < addr` and `is_clk_lt` is set to `next_clk_word < clk_word`. We can use
        // these assumptions when constraining the equality flags below.

        // Constrain untrusted booleans to be either 0 or 1.
        local.is_read.eval_is_valid(builder);
        local.is_addr_eq.eval_is_valid(builder);
        local.is_clk_eq.eval_is_valid(builder);

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
        for (byte, byte_next) in local.addr.into_iter().zip(next.addr) {
            builder
                .when_transition()
                .assert_zero((next.is_addr_eq - AB::F::one()) * (byte - byte_next));
        }

        // Assert that when the address remains the same, the value of the clock cycle is
        // non-decreasing, and the validity of `is_clk_eq`. We will use checks analogous to the ones
        // above for address, filtered by the condition that the address is equal to the previous
        // address.
        builder
            .when_transition()
            .when(next.is_addr_eq.0)
            .assert_one(next.is_clk_lt.0 + next.is_clk_eq.0);
        // For the assertion that `is_clk_eq` is one when the clock cycle is equal to the previous
        // one, we do not filter by the address condition to preserve the degree of the constraint.
        builder
            .when_transition()
            .assert_zero((next.is_clk_eq - AB::F::one()) * (next.clk - local.clk));
    }
}

impl MemoryAir {
    pub fn sends<F: Field>(&self) -> Vec<Interaction<F>> {
        // Memory chip needs a lookup for less than equal operations.
        todo!()
    }

    pub fn recieves<F: Field>(&self) -> Vec<Interaction<F>> {
        // Memory chip accepts all the memory requests
        vec![MemoryInteraction::new(
            VirtualPairCol::single_main(MEM_COL.clk),
            MEM_COL.addr.map(VirtualPairCol::single_main),
            MEM_COL.value.map(VirtualPairCol::single_main),
            VirtualPairCol::single_main(MEM_COL.multiplicity),
            VirtualPairCol::single_main(MEM_COL.is_read.0),
        )
        .into()]
    }
}
