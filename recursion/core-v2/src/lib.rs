use std::iter::once;

use serde::{Deserialize, Serialize};
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

#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Address<F>(pub F);

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
    pub opcode: BaseAluOpcode,
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
    pub opcode: ExtAluOpcode,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}
