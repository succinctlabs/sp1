use std::sync::Arc;

use p3_field::{AbstractField, PrimeField32};
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
    pub public_values_digest: RecursivePublicValues<F>,
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

    fn serialized_public_values<T: AbstractField>(&self) -> Vec<T> {
        self.public_values_digest.to_field_elms()
    }
}

#[derive(Default, Debug, Clone)]
pub struct RecursivePublicValues<F: Default>(pub [F; DIGEST_SIZE]);

impl<F: AbstractField> RecursivePublicValues<F> {
    pub fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}

impl<F: PrimeField32> RecursivePublicValues<F> {
    pub fn to_field_elms<T: AbstractField>(&self) -> Vec<T> {
        self.0
            .iter()
            .map(|f| T::from_canonical_u32(F::as_canonical_u32(f)))
            .collect()
    }
}
