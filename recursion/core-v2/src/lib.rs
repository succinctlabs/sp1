use std::collections::HashMap;

use p3_field::PrimeField32;
use sp1_core::stark::MachineRecord;

pub mod add;

// #[derive(Clone, Debug)]
// pub struct Address;
// pub type Address = u32;

// I don't think events should depend on the field being used,
// but I don't want to implement encoding or memory yet
#[derive(Clone, Debug)]
pub struct AluEvent<F> {
    pub opcode: Opcode,
    pub a: F,
    pub b: F,
    pub c: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opcode {
    Add,
    Mul,
}

#[derive(Clone, Default, Debug)]
pub struct ExecutionRecord<F> {
    pub add_events: Vec<AluEvent<F>>,
    // _data: std::marker::PhantomData<F>,
    // pub vars: HashMap<Address, u32>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ();

    fn index(&self) -> u32 {
        todo!()
    }

    fn set_index(&mut self, _index: u32) {
        todo!()
    }

    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        todo!()
    }

    fn append(&mut self, _other: &mut Self) {
        todo!()
    }

    fn shard(self, _config: &Self::Config) -> Vec<Self> {
        todo!()
    }

    fn public_values<T: p3_field::AbstractField>(&self) -> Vec<T> {
        todo!()
    }
}
