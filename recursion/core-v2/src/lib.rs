use std::collections::HashMap;

use p3_field::PrimeField32;
use sp1_core::{air::PublicValues, stark::MachineRecord};

pub mod add;
// pub mod builder;
pub mod machine;
pub mod mem;
// pub mod mul;
pub mod program;

// #[derive(Clone, Debug)]
// pub struct Address;
// pub type Address = u32;

// I don't think events should depend on the field being used,
// but I don't want to implement encoding or memory yet
#[derive(Clone, Debug)]
pub struct AluEvent<F> {
    pub opcode: Opcode,
    pub a: AddressValue<F>,
    pub b: AddressValue<F>,
    pub c: AddressValue<F>,
    pub mult: F, // number of times we need this value in the future
}

#[derive(Clone, Debug)]
pub struct MemEvent<F> {
    pub address_value: AddressValue<F>,
    pub multiplicity: F,
    pub kind: MemAccessKind,
}

#[derive(Clone, Debug)]
pub enum MemAccessKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressValue<F> {
    addr: F,
    val: F,
}

impl<F> AddressValue<F> {
    fn new(addr: F, val: F) -> Self {
        Self { addr, val }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opcode {
    Add,
    Mul,
}

#[derive(Clone, Default, Debug)]
pub struct ExecutionRecord<F> {
    /// The index of the shard.
    pub index: u32,

    pub add_events: Vec<AluEvent<F>>,
    pub mul_events: Vec<AluEvent<F>>,
    pub mem_events: Vec<MemEvent<F>>,
    // _data: std::marker::PhantomData<F>,
    // pub vars: HashMap<Address, u32>,
    /// The public values.
    pub public_values: PublicValues<u32, u32>,
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
        self.add_events.append(&mut other.add_events);
        self.mul_events.append(&mut other.mul_events);
        self.mem_events.append(&mut other.mem_events);
    }

    fn shard(self, _config: &Self::Config) -> Vec<Self> {
        vec![self]
    }

    fn public_values<T: p3_field::AbstractField>(&self) -> Vec<T> {
        self.public_values.to_vec()
    }
}

use p3_field::Field;
use serde::{Deserialize, Serialize};
use sp1_core::air::MachineProgram;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    // pub instructions: Vec<Instruction<F>>,
    // #[serde(skip)]
    // pub traces: Vec<Option<Backtrace>>,
    _data: std::marker::PhantomData<F>,
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }
}
