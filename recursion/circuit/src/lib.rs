#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]

use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;
use sp1_recursion_compiler::ir::Config;

pub mod challenger;
pub mod fri;
pub mod poseidon2;

pub const DIGEST_SIZE: usize = 3;

#[derive(Clone, Default)]
pub struct GnarkConfig;

impl Config for GnarkConfig {
    type N = Bn254Fr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
