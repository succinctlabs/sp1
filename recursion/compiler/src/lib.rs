#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;
use prelude::Config;
extern crate alloc;

pub mod asm;
pub mod constraints;
pub mod ir;
pub mod util;

pub mod prelude {
    pub use crate::asm::AsmCompiler;
    pub use crate::ir::*;
    pub use sp1_recursion_derive::DslVariable;
}

#[derive(Clone, Default, Debug)]
pub struct InnerConfig;

impl Config for InnerConfig {
    type N = BabyBear;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = Bn254Fr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
