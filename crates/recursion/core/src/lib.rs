use p3_field::PrimeField64;
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;

use crate::air::{Block, RecursionPublicValues};

pub mod air;
pub mod builder;
pub mod chips;
pub mod machine;
pub mod runtime;
pub mod shape;
pub mod stark;

pub use runtime::*;

// Re-export the stark stuff from `sp1_recursion_core` for now, until we will migrate it here.
// pub use sp1_recursion_core::stark;

use crate::chips::poseidon2_skinny::WIDTH;

#[derive(
    AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[repr(transparent)]
pub struct Address<F>(pub F);

impl<F: PrimeField64> Address<F> {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0.as_canonical_u64() as usize
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the base field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemIo<V> {
    pub inner: V,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInstr<F> {
    pub addrs: MemIo<Address<F>>,
    pub vals: MemIo<Block<F>>,
    pub mult: F,
    pub kind: MemAccessKind,
}

pub type MemEvent<F> = MemIo<Block<F>>;

// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}

/// The inputs and outputs to a Poseidon2 permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poseidon2Io<V> {
    pub input: [V; WIDTH],
    pub output: [V; WIDTH],
}

/// An instruction invoking the Poseidon2 permutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Poseidon2SkinnyInstr<F> {
    pub addrs: Poseidon2Io<Address<F>>,
    pub mults: [F; WIDTH],
}

pub type Poseidon2Event<F> = Poseidon2Io<F>;

/// The inputs and outputs to a select digest operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectIo<V> {
    pub bit: V,
    pub out1: V,
    pub out2: V,
    pub in1: V,
    pub in2: V,
}

/// An instruction invoking the select digest operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SelectInstr<F> {
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

/// The event encoding the inputs and outputs of a select digest operation.
pub type SelectEvent<F> = SelectIo<F>;

/// The inputs and outputs to an exp-reverse-bits operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsIo<V> {
    pub base: V,
    // The bits of the exponent in little-endian order in a vec.
    pub exp: Vec<V>,
    pub result: V,
}

pub type Poseidon2WideEvent<F> = Poseidon2Io<F>;
pub type Poseidon2Instr<F> = Poseidon2SkinnyInstr<F>;

/// An instruction invoking the exp-reverse-bits operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpReverseBitsInstr<F> {
    pub addrs: ExpReverseBitsIo<Address<F>>,
    pub mult: F,
}

/// The event encoding the inputs and outputs of an exp-reverse-bits operation. The `len` operand is
/// now stored as the length of the `exp` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsEvent<F> {
    pub base: F,
    pub exp: Vec<F>,
    pub result: F,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldIo<V> {
    pub ext_single: FriFoldExtSingleIo<Block<V>>,
    pub ext_vec: FriFoldExtVecIo<Vec<Block<V>>>,
    pub base_single: FriFoldBaseIo<V>,
}

/// The extension-field-valued single inputs to the FRI fold operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldExtSingleIo<V> {
    pub z: V,
    pub alpha: V,
}

/// The extension-field-valued vector inputs to the FRI fold operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldExtVecIo<V> {
    pub mat_opening: V,
    pub ps_at_z: V,
    pub alpha_pow_input: V,
    pub ro_input: V,
    pub alpha_pow_output: V,
    pub ro_output: V,
}

/// The base-field-valued inputs to the FRI fold operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldBaseIo<V> {
    pub x: V,
}

/// An instruction invoking the FRI fold operation. Addresses for extension field elements are of
/// the same type as for base field elements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldInstr<F> {
    pub base_single_addrs: FriFoldBaseIo<Address<F>>,
    pub ext_single_addrs: FriFoldExtSingleIo<Address<F>>,
    pub ext_vec_addrs: FriFoldExtVecIo<Vec<Address<F>>>,
    pub alpha_pow_mults: Vec<F>,
    pub ro_mults: Vec<F>,
}

/// The event encoding the data of a single iteration within the FRI fold operation.
/// For any given event, we are accessing a single element of the `Vec` inputs, so that the event
/// is not a type alias for `FriFoldIo` like many of the other events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldEvent<F> {
    pub base_single: FriFoldBaseIo<F>,
    pub ext_single: FriFoldExtSingleIo<Block<F>>,
    pub ext_vec: FriFoldExtVecIo<Block<F>>,
}

/// An instruction that will save the public values to the execution record and will commit to
/// it's digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitPublicValuesInstr<F> {
    pub pv_addrs: RecursionPublicValues<Address<F>>,
}

/// The event for committing to the public values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitPublicValuesEvent<F> {
    pub public_values: RecursionPublicValues<F>,
}
