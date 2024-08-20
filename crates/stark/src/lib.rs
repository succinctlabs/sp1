//! STARK-based primitives for proof generation and verification over AIRs.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::if_not_else)]
#![warn(missing_docs)]

pub mod air;
mod bb31_poseidon2;
mod chip;
mod config;
mod debug;
mod folder;
mod lookup;
mod machine;
mod opts;
mod permutation;
mod prover;
mod quotient;
mod record;
mod types;
mod util;
mod verifier;
mod word;

pub use bb31_poseidon2::*;
pub use chip::*;
pub use config::*;
pub use debug::*;
pub use folder::*;
pub use lookup::*;
pub use machine::*;
pub use opts::*;
pub use permutation::*;
pub use prover::*;
pub use quotient::*;
pub use record::*;
pub use types::*;
pub use verifier::*;
pub use word::*;
