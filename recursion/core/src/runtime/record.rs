use std::sync::Arc;

use hashbrown::HashMap;
use p3_field::PrimeField32;
use sp1_core::stark::MachineRecord;

use crate::cpu::CpuEvent;
use crate::runtime::MemoryRecord;

use super::Program;

#[derive(Default, Debug, Clone)]
pub struct ExecutionRecord<F: Default> {
    pub program: Arc<Program<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,
    pub first_memory_record: Vec<(u32, MemoryRecord<F>, u32)>,
    pub last_memory_record: Vec<(u32, MemoryRecord<F>, u32)>,
    pub program_memory_record: Vec<(u32, MemoryRecord<F>, u32)>,
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

    fn append(&mut self, _: &mut Self) {}

    fn shard(self, _: &Self::Config) -> Vec<Self> {
        vec![self]
    }
}
