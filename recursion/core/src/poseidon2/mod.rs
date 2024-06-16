#![allow(clippy::needless_range_loop)]

use std::usize;

use crate::poseidon2::external::WIDTH;
mod columns;
pub mod external;
mod trace;
use crate::air::Block;
use crate::memory::MemoryRecord;
use crate::runtime::DIGEST_SIZE;
use p3_field::PrimeField32;

pub use columns::Poseidon2Cols;
pub use external::Poseidon2Chip;

#[derive(Debug, Clone)]
pub enum Poseidon2HashEvent<F> {
    Absorb(Poseidon2AbsorbEvent<F>),
    Finalize(Poseidon2FinalizeEvent<F>),
}

#[derive(Debug, Clone)]
pub struct Poseidon2CompressEvent<F> {
    pub clk: F,
    pub dst: F,   // from a_val
    pub left: F,  // from b_val
    pub right: F, // from c_val
    pub input: [F; WIDTH],
    pub result_array: [F; WIDTH],
    pub input_records: [MemoryRecord<F>; WIDTH],
    pub result_records: [MemoryRecord<F>; WIDTH],
    pub dummy_output_permutation: [F; WIDTH],
}

impl<F: PrimeField32> Poseidon2CompressEvent<F> {
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
            dummy_output_permutation: [F::zero(); WIDTH],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Poseidon2AbsorbIteration<F> {
    pub state_cursor: usize,
    pub start_addr: F,
    pub input_records: Vec<MemoryRecord<F>>,
    pub perm_input: [F; WIDTH],
    pub perm_output: [F; WIDTH],

    pub previous_state: [F; WIDTH],
    pub state: [F; WIDTH],
    pub do_perm: bool,
    pub num_consumed: usize,
    pub remaining_len: usize,
}

#[derive(Debug, Clone)]
pub struct Poseidon2AbsorbEvent<F> {
    pub clk: F,
    pub hash_num: F,      // from a_val
    pub input_ptr: F,     // from b_val
    pub input_len: usize, // from c_val
    pub absorb_iterations: Vec<Poseidon2AbsorbIteration<F>>,
    pub is_hash_first_absorb: bool,
}

#[derive(Debug, Clone)]
pub struct Poseidon2FinalizeEvent<F> {
    pub clk: F,
    pub hash_num: F,   // from a_val
    pub output_ptr: F, // from b_val
    pub do_perm: bool,
    pub perm_input: [F; WIDTH],
    pub perm_output: [F; WIDTH],
    pub previous_state: [F; WIDTH],
    pub state: [F; WIDTH],
    pub state_cursor: usize,
    pub output_records: [MemoryRecord<F>; DIGEST_SIZE],
}
