pub mod air;
pub mod columns;
pub mod event;
pub mod opcode;
pub mod trace;

pub use event::RangeCheckEvent;
pub use opcode::*;

use alloc::collections::BTreeMap;
use core::borrow::BorrowMut;
use std::marker::PhantomData;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use self::columns::{RangeCheckPreprocessedCols, NUM_RANGE_CHECK_PREPROCESSED_COLS};
use crate::range_check::trace::NUM_ROWS;

/// The number of different range check operations.
pub const NUM_RANGE_CHECK_OPS: usize = 2;

/// A chip for computing range check operations.
///
/// The chip contains a preprocessed table of all possible range check operations. Other chips can
/// then use lookups into this table to range check their values.
#[derive(Debug, Clone, Copy, Default)]
pub struct RangeCheckChip<F>(PhantomData<F>);

impl<F: Field> RangeCheckChip<F> {
    /// Creates the preprocessed range check trace and event map.
    ///
    /// This function returns a pair `(trace, map)`, where:
    ///  - `trace` is a matrix containing all possible range check values.
    /// - `map` is a map from a range check lookup to the value's corresponding row it appears in
    ///   the table and
    /// the index of the result in the array of multiplicities.
    pub fn trace_and_map() -> (RowMajorMatrix<F>, BTreeMap<RangeCheckEvent, (usize, usize)>) {
        // A map from a byte lookup to its corresponding row in the table and index in the array of
        // multiplicities.
        let mut event_map = BTreeMap::new();

        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_ROWS * NUM_RANGE_CHECK_PREPROCESSED_COLS],
            NUM_RANGE_CHECK_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each range check lookup.
        let opcodes = RangeCheckOpcode::all();

        // Iterate over all U16 values.
        for (row_index, val) in (0..=u16::MAX).enumerate() {
            let col: &mut RangeCheckPreprocessedCols<F> =
                initial_trace.row_mut(row_index).borrow_mut();

            // Set the u16 value.
            col.value_u16 = F::from_canonical_u16(val);

            // Iterate over all range check operations to update col values and the table map.
            for (i, opcode) in opcodes.iter().enumerate() {
                if *opcode == RangeCheckOpcode::U12 {
                    col.u12_out_range = F::from_bool(val > 0xFFF);
                }

                let event = RangeCheckEvent::new(*opcode, val);
                event_map.insert(event, (row_index, i));
            }
        }

        (initial_trace, event_map)
    }
}
