#![allow(
    clippy::eq_op,
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap,
    clippy::default_constructed_unit_structs,
    clippy::box_default,
    deprecated,
    incomplete_features
)]
#![feature(generic_const_exprs)]
#![warn(unused_extern_crates)]

extern crate alloc;

pub mod air;
pub mod alu;
pub mod bytes;
pub mod cpu;
pub mod disassembler;
#[deprecated(note = "Import from sp1_sdk instead of sp1_core")]
pub mod io;
pub mod lookup;
pub mod memory;
pub mod operations;
pub mod program;
pub mod runtime;
pub mod stark;
pub mod syscall;
pub mod utils;

pub use io::*;

#[allow(unused_imports)]
use runtime::{Program, Runtime};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stark::Proof;
use stark::StarkGenericConfig;

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
#[deprecated(note = "Import from sp1_sdk instead of sp1_core")]
pub struct SP1ProofWithIO<SC: StarkGenericConfig + Serialize + DeserializeOwned> {
    #[serde(with = "proof_serde")]
    pub proof: Proof<SC>,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}
