#![allow(clippy::needless_range_loop)]

use crate::poseidon2::external::WIDTH;
mod columns;
pub mod external;
mod trace;
use crate::air::Block;
use crate::memory::MemoryRecord;
use p3_field::PrimeField32;

pub use columns::Poseidon2Cols;
pub use external::Poseidon2Chip;

#[derive(Debug, Clone)]
pub struct Poseidon2Event<F> {
    pub clk: F,
    pub dst: F,   // from a_val
    pub left: F,  // from b_val
    pub right: F, // from c_val
    pub input: [F; WIDTH],
    pub result_array: [F; WIDTH],
    pub input_records: [MemoryRecord<F>; WIDTH],
    pub result_records: [MemoryRecord<F>; WIDTH],
}

impl<F: PrimeField32> Poseidon2Event<F> {
    /// A way to construct a dummy event from an input array, used for testing.
    pub fn dummy_from_input(input: [F; WIDTH], output: [F; WIDTH]) -> Self {
        let input_records = core::array::from_fn(|i| {
            MemoryRecord::new_read(F::zero(), Block::from(input[i]), F::one(), F::zero())
        });
        let output_records: [MemoryRecord<F>; WIDTH] = core::array::from_fn(|i| {
            MemoryRecord::new_read(F::zero(), Block::from(output[i]), F::two(), F::zero())
        });

        Self {
            clk: F::one(),
            dst: F::zero(),
            left: F::zero(),
            right: F::zero(),
            input,
            result_array: [F::zero(); WIDTH],
            input_records,
            result_records: output_records,
        }
    }
}
