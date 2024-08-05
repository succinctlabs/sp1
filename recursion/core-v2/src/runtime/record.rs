use std::sync::Arc;

use p3_field::PrimeField32;
use sp1_core::{air::PublicValues, stark::MachineRecord, utils::SP1CoreOpts};

// TODO expand glob imports
use crate::*;

#[derive(Clone, Default, Debug)]
pub struct ExecutionRecord<F> {
    pub program: Arc<RecursionProgram<F>>,
    /// The index of the shard.
    pub index: u32,

    pub base_alu_events: Vec<BaseAluEvent<F>>,
    pub ext_alu_events: Vec<ExtAluEvent<F>>,
    pub mem_const_count: usize,
    pub mem_var_events: Vec<MemEvent<F>>,
    /// The public values.
    pub public_values: PublicValues<u32, u32>,

    pub poseidon2_skinny_events: Vec<Poseidon2SkinnyEvent<F>>,
    pub poseidon2_wide_events: Vec<Poseidon2WideEvent<F>>,
    pub exp_reverse_bits_len_events: Vec<ExpReverseBitsEvent<F>>,
    pub fri_fold_events: Vec<FriFoldEvent<F>>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = SP1CoreOpts;

    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        hashbrown::HashMap::from([("cpu_events".to_owned(), 1337usize)])
    }

    fn append(&mut self, other: &mut Self) {
        // Exhaustive destructuring for refactoring purposes.
        let Self {
            program: _,
            index: _,
            base_alu_events,
            ext_alu_events,
            mem_const_count,
            mem_var_events,
            public_values: _,
            poseidon2_wide_events,
            poseidon2_skinny_events,
            exp_reverse_bits_len_events,
            fri_fold_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        *mem_const_count += other.mem_const_count;
        mem_var_events.append(&mut other.mem_var_events);
        poseidon2_wide_events.append(&mut other.poseidon2_wide_events);
        poseidon2_skinny_events.append(&mut other.poseidon2_skinny_events);
        exp_reverse_bits_len_events.append(&mut other.exp_reverse_bits_len_events);
        fri_fold_events.append(&mut other.fri_fold_events);
    }

    fn public_values<T: p3_field::AbstractField>(&self) -> Vec<T> {
        self.public_values.to_vec()
    }
}
