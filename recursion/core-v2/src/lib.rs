use std::iter::once;

use p3_field::PrimeField32;
use sp1_core::{air::PublicValues, stark::MachineRecord};

pub mod alu;
// pub mod builder;
pub mod machine;
pub mod mem;
pub mod program;

// #[derive(Clone, Debug)]
// pub struct Address;
// pub type Address = u32;

// I don't think events should depend on the field being used,
// but I don't want to implement encoding or memory yet
#[derive(Clone, Debug)]
pub struct AluEvent<F> {
    pub opcode: Opcode,
    pub out: AddressValue<F>,
    pub in1: AddressValue<F>,
    pub in2: AddressValue<F>,
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
    val: Block<F>,
}

impl<F> AddressValue<F> {
    pub fn new(addr: F, val: Block<F>) -> Self {
        Self { addr, val }
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &F> {
        once(&self.addr).chain(self.val.0.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut F> {
        once(&mut self.addr).chain(self.val.0.iter_mut())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opcode {
    AddF,
    SubF,
    MulF,
    DivF,
    AddE,
    SubE,
    MulE,
    DivE,
}

#[derive(Clone, Default, Debug)]
pub struct ExecutionRecord<F> {
    /// The index of the shard.
    pub index: u32,

    pub alu_events: Vec<AluEvent<F>>,
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
        // Exhaustive destructuring for refactoring purposes.
        let Self {
            index: _,
            alu_events,
            mem_events,
            public_values: _,
        } = self;
        alu_events.append(&mut other.alu_events);
        mem_events.append(&mut other.mem_events);
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
use sp1_recursion_core::air::Block;

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
