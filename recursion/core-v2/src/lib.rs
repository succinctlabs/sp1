use std::iter::once;

use p3_field::{Field, PrimeField32};
use serde::{Deserialize, Serialize};
use sp1_core::air::MachineProgram;
use sp1_core::{air::PublicValues, stark::MachineRecord};
use sp1_derive::AlignedBorrow;
use sp1_recursion_core::{air::Block, runtime::D};

pub mod alu_base;
pub mod alu_ext;
pub mod builder;
pub mod machine;
pub mod mem;
pub mod program;

// #[derive(Clone, Debug)]
// pub struct Address;
// pub type Address = u32;

// I don't think events should depend on the field being used,
// but I don't want to implement encoding or memory yet
#[derive(Clone, Debug)]
pub struct BaseAluEvent<F> {
    pub opcode: Opcode,
    pub out: AddressValue<F, F>,
    pub in1: AddressValue<F, F>,
    pub in2: AddressValue<F, F>,
    pub mult: F, // number of times we need this value in the future
}

#[derive(Clone, Debug)]
pub struct ExtAluEvent<F> {
    pub opcode: Opcode,
    pub out: AddressValue<F, Block<F>>,
    pub in1: AddressValue<F, Block<F>>,
    pub in2: AddressValue<F, Block<F>>,
    pub mult: F, // number of times we need this value in the future
}

#[derive(Clone, Debug)]
pub struct MemEvent<F> {
    pub address_value: AddressValue<F, Block<F>>,
    pub multiplicity: F,
    pub kind: MemAccessKind,
}

#[derive(Clone, Debug)]
pub enum MemAccessKind {
    Read,
    Write,
}

#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
/// A memory address along with the stored value.
/// For alignment reasons, `val` is first --- in `AddressValue<F, Block<F>>`, `val` is well-aligned.
pub struct AddressValue<A, V> {
    val: V,
    addr: A,
}

impl<A, V> AddressValue<A, V> {
    pub fn new(addr: A, val: V) -> Self {
        Self { addr, val }
    }
}

// impl<F> IntoIterator for AddressValue<F, F> {
//     type Item = F;

//     type IntoIter = std::array::IntoIter<F, 2>;

//     fn into_iter(self) -> Self::IntoIter {
//         let Self { addr, val } = self;
//         [addr, val].into_iter()
//     }
// }

impl<F> IntoIterator for AddressValue<F, Block<F>> {
    type Item = F;

    type IntoIter = std::iter::Chain<std::iter::Once<F>, std::array::IntoIter<F, D>>;

    fn into_iter(self) -> Self::IntoIter {
        let Self { addr, val } = self;
        once(addr).chain(val)
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

    pub base_alu_events: Vec<BaseAluEvent<F>>,
    pub ext_alu_events: Vec<ExtAluEvent<F>>,
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
            base_alu_events,
            ext_alu_events,
            mem_events,
            public_values: _,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        mem_events.append(&mut other.mem_events);
    }

    fn shard(self, _config: &Self::Config) -> Vec<Self> {
        vec![self]
    }

    fn public_values<T: p3_field::AbstractField>(&self) -> Vec<T> {
        self.public_values.to_vec()
    }
}

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
