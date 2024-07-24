//! Copied from [`sp1_recursion_program`].

use sp1_recursion_compiler::ir::{Config, Felt};
use sp1_recursion_core_v2::DIGEST_SIZE;

pub mod build_wrap_v2;
pub mod challenger;
pub mod fri;

pub type DigestVariable<C> = [Felt<<C as Config>::F>; DIGEST_SIZE];
