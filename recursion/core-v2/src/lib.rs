use std::iter::once;

use p3_field::{Field, PrimeField32};
use serde::{Deserialize, Serialize};
use sp1_core::air::MachineProgram;
use sp1_core::{air::PublicValues, stark::MachineRecord};
use sp1_derive::AlignedBorrow;
use sp1_recursion_core::air::Block;

pub mod alu_base;
pub mod alu_ext;
pub mod builder;
pub mod machine;
pub mod mem;
pub mod program;
pub mod runtime;

pub use runtime::*;

// an Instruction should be an event, but with addresses... right? what else does it need to be?
// yes, because instructions form a generating list of events,
// which reduce into more events and constraints in the chips/AIRs
// trait Operation<T> {
//     const ARITY_IN: usize;
//     const ARITY_OUT: usize = 1;

//     const OPCODE: Opcode;
// }

// struct Operation<const ARITY_IN: usize, const ARITY_OUT: usize, T> {
//     pub opcode: Opcode,
//     pub input: [T; ARITY_IN],
//     pub output: [T; ARITY_OUT],
// }

// type Instr<const ARITY_IN: usize, const ARITY_OUT: usize, F> =
//     Operation<ARITY_IN, ARITY_OUT, Block<F>>;

// type Op<const ARITY_IN: usize, const ARITY_OUT: usize, F> =
//     Operation<ARITY_IN, ARITY_OUT, Block<F>>;

// #[derive(Clone, Debug)]
// pub struct Address;
// pub type Address = u32;

#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Address<F>(F);

// I don't think events should depend on the field being used,
// but I don't want to implement encoding or memory yet
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct BaseAluOp<F, V> {
//     pub opcode: Opcode,
//     pub out: V,
//     pub in1: V,
//     pub in2: V,
//     pub mult: F, // number of times we need this value in the future
// }

// pub type BaseAluInstr<F> = BaseAluOp<F, Address<F>>;
// #[deprecated]
// pub type BaseAluEventOld<F> = BaseAluOp<F, AddressValue<F, F>>;
// pub type BaseAluEvent<F> = BaseAluOp<F, F>;

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the base field ALU.
#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

pub type BaseAluEvent<F> = BaseAluIo<F>;

/// An instruction invoking the extension field ALU.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaseAluInstr<F> {
    pub opcode: Opcode,
    pub mult: F,
    pub addrs: BaseAluIo<Address<F>>,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the extension field ALU.
#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

pub type ExtAluEvent<F> = ExtAluIo<Block<F>>;

/// An instruction invoking the extension field ALU.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtAluInstr<F> {
    pub opcode: Opcode,
    pub mult: F,
    pub addrs: ExtAluIo<Address<F>>,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to the manual memory management/memory initialization table.
#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemIo<V> {
    pub inner: V,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemInstr<F> {
    pub addrs: MemIo<Address<F>>,
    pub vals: MemIo<Block<F>>,
    pub mult: F,
    pub kind: MemAccessKind,
}

pub type MemEvent<F> = MemIo<Block<F>>;

// -------------------------------------------------------------------------------------------------

// pub type MemInstr<F> = MemOp<F, F>;
// pub type MemInstr<F> = MemOp<F, AddressValue<F, Block<F>>>;
// #[deprecated]
// pub type MemEventOld<F> = MemOp<F, AddressValue<F, Block<F>>>;
// pub type MemEvent<F> = MemOp<F, Block<F>>;
// pub type MemEvent<F> = MemOp<F, AddressValue<F, Block<F>>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}
