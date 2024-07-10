use std::sync::Arc;

use p3_field::PrimeField32;
use sp1_core::{air::PublicValues, stark::MachineRecord};

// TODO expand glob imports
use crate::*;

#[derive(Clone, Default, Debug)]
pub struct ExecutionRecord<F> {
    pub program: Arc<RecursionProgram<F>>,
    /// The index of the shard.
    pub index: u32,

    pub base_alu_events: Vec<BaseAluEvent<F>>,
    pub ext_alu_events: Vec<ExtAluEvent<F>>,
    pub mem_events: Vec<MemEvent<F>>,
    /// The public values.
    pub public_values: PublicValues<u32, u32>,

    pub poseidon2_wide_events: Vec<Poseidon2WideEvent<F>>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ();

    fn index(&self) -> u32 {
        self.index
    }

    fn set_index(&mut self, index: u32) {
        self.index = index;
    }

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
            mem_events,
            public_values: _,
            poseidon2_wide_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        mem_events.append(&mut other.mem_events);
        poseidon2_wide_events.append(&mut other.poseidon2_wide_events);
    }

    fn shard(self, _config: &Self::Config) -> Vec<Self> {
        vec![self]
    }

    fn public_values<T: p3_field::AbstractField>(&self) -> Vec<T> {
        self.public_values.to_vec()
    }
}
