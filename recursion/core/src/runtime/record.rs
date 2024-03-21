use std::sync::Arc;

use p3_field::PrimeField32;
use sp1_core::stark::MachineRecord;
use std::collections::HashMap;

use super::Program;
use crate::air::Block;
use crate::cpu::CpuEvent;
use crate::poseidon2::Poseidon2Event;

#[derive(Default, Debug, Clone)]
pub struct ExecutionRecord<F: Default> {
    pub program: Arc<Program<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,

    // poseidon2 events
    pub poseidon2_events: Vec<Poseidon2Event<F>>,

    // (address)
    pub first_memory_record: Vec<F>,

    // (address, last_timestamp, last_value)
    pub last_memory_record: Vec<(F, F, Block<F>)>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ();

    fn index(&self) -> u32 {
        0
    }

    fn set_index(&mut self, _: u32) {}

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("poseidon2_events".to_string(), self.poseidon2_events.len());
        stats
    }

    fn append(&mut self, other: &mut Self) {
        self.poseidon2_events.append(&mut other.poseidon2_events);
    }

    fn shard(self, _: &Self::Config) -> Vec<Self> {
        vec![self]
    }
}
