use std::sync::Arc;

use p3_field::PrimeField32;
use sp1_core::air::PublicValues;
use sp1_core::stark::MachineRecord;
use std::collections::HashMap;

use super::{Program, DIGEST_SIZE};
use crate::air::Block;
use crate::cpu::CpuEvent;

#[derive(Default, Debug, Clone)]
pub struct ExecutionRecord<F: Default> {
    pub program: Arc<Program<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,

    // (address)
    pub first_memory_record: Vec<F>,

    // (address, last_timestamp, last_value)
    pub last_memory_record: Vec<(F, F, Block<F>)>,

    /// The public values.
    pub public_values_digest: [F; DIGEST_SIZE],
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ();

    fn index(&self) -> u32 {
        0
    }

    fn set_index(&mut self, _: u32) {}

    fn stats(&self) -> HashMap<String, usize> {
        HashMap::new()
    }

    fn append(&mut self, other: &mut Self) {
        self.cpu_events.append(&mut other.cpu_events);
        self.first_memory_record
            .append(&mut other.first_memory_record);
        self.last_memory_record
            .append(&mut other.last_memory_record);
    }

    fn shard(self, _: &Self::Config) -> Vec<Self> {
        vec![self]
    }

    fn public_values(&self) -> PublicValues<u32, u32> {
        PublicValues::default()
    }
}
