#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

extern crate alloc;

use asm::AsmConfig;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;
use prelude::Config;
use sp1_recursion_core::stark::config::{InnerChallenge, InnerVal};

pub mod asm;
pub mod constraints;
pub mod ir;
pub mod util;

pub mod prelude {
    pub use crate::asm::AsmCompiler;
    pub use crate::ir::*;
    pub use sp1_recursion_derive::DslVariable;
}

pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = Bn254Fr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
