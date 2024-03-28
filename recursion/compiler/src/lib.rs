#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;
use prelude::Config;
extern crate alloc;

pub mod asm;
pub mod gnark;
pub mod ir;
pub mod r1cs;
pub mod util;
pub mod verifier;

pub mod prelude {
    pub use crate::asm::AsmCompiler;
    pub use crate::ir::*;
}

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = Bn254Fr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
