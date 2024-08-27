use p3_field::PrimeField32;
use p3_symmetric::Permutation;

use crate::{memory::MemoryRecord, poseidon2_wide::WIDTH, runtime::DIGEST_SIZE};

use super::RATE;

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
}

#[derive(Debug, Clone)]
pub struct Poseidon2AbsorbEvent<F> {
    pub clk: F,
    pub hash_and_absorb_num: F, // from a_val
    pub input_addr: F,          // from b_val
    pub input_len: F,           // from c_val

    pub hash_num: F,
    pub absorb_num: F,
    pub iterations: Vec<Poseidon2AbsorbIteration<F>>,
}

impl<F> Poseidon2AbsorbEvent<F> {
    pub(crate) fn new(
        clk: F,
        hash_and_absorb_num: F,
        input_addr: F,
        input_len: F,
        hash_num: F,
        absorb_num: F,
    ) -> Self {
        Self {
            clk,
            hash_and_absorb_num,
            input_addr,
            input_len,
            hash_num,
            absorb_num,
            iterations: Vec::new(),
        }
    }
}

impl<F: PrimeField32> Poseidon2AbsorbEvent<F> {
    pub(crate) fn populate_iterations(
        &mut self,
        start_addr: F,
        input_len: F,
        memory_records: &[MemoryRecord<F>],
        permuter: &impl Permutation<[F; WIDTH]>,
        hash_state: &mut [F; WIDTH],
        hash_state_cursor: &mut usize,
    ) -> usize {
        let mut nb_permutes = 0;
        let mut input_records = Vec::new();
        let mut previous_state = *hash_state;
        let mut iter_num_consumed = 0;

        let start_addr = start_addr.as_canonical_u32();
        let end_addr = start_addr + input_len.as_canonical_u32();

        for (addr_iter, memory_record) in (start_addr..end_addr).zip(memory_records.iter()) {
            input_records.push(*memory_record);

            hash_state[*hash_state_cursor] = memory_record.value[0];
            *hash_state_cursor += 1;
            iter_num_consumed += 1;

            // Do a permutation when the hash state is full.
            if *hash_state_cursor == RATE {
                nb_permutes += 1;
                let perm_input = *hash_state;
                *hash_state = permuter.permute(*hash_state);

                self.iterations.push(Poseidon2AbsorbIteration {
                    state_cursor: *hash_state_cursor - iter_num_consumed,
                    start_addr: F::from_canonical_u32(addr_iter - iter_num_consumed as u32 + 1),
                    input_records,
                    perm_input,
                    perm_output: *hash_state,
                    previous_state,
                    state: *hash_state,
                    do_perm: true,
                });

                previous_state = *hash_state;
                input_records = Vec::new();
                *hash_state_cursor = 0;
                iter_num_consumed = 0;
            }
        }

        if *hash_state_cursor != 0 {
            nb_permutes += 1;
            // Note that we still do a permutation, generate the trace and enforce permutation
            // constraints for every absorb and finalize row.
            self.iterations.push(Poseidon2AbsorbIteration {
                state_cursor: *hash_state_cursor - iter_num_consumed,
                start_addr: F::from_canonical_u32(end_addr - iter_num_consumed as u32),
                input_records,
                perm_input: *hash_state,
                perm_output: permuter.permute(*hash_state),
                previous_state,
                state: *hash_state,
                do_perm: false,
            });
        }
        nb_permutes
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
}

#[derive(Debug, Clone)]
pub struct Poseidon2FinalizeEvent<F> {
    pub clk: F,
    pub hash_num: F,   // from a_val
    pub output_ptr: F, // from b_val
    pub output_records: [MemoryRecord<F>; DIGEST_SIZE],

    pub state_cursor: usize,

    pub perm_input: [F; WIDTH],
    pub perm_output: [F; WIDTH],

    pub previous_state: [F; WIDTH],
    pub state: [F; WIDTH],

    pub do_perm: bool,
}
