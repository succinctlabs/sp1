#![allow(clippy::assign_op_pattern)]

pub mod ir;

use slop_algebra::extension::BinomialExtensionField;
use sp1_primitives::SP1Field;

pub type F = SP1Field;

pub type EF = BinomialExtensionField<F, 4>;
