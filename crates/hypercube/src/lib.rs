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
mod chip;
mod debug;
mod folder;
pub mod ir;
mod logup_gkr;
mod lookup;
mod machine;
pub mod operations;
pub mod prover;
mod record;
/// Public values for recursion proofs.
pub mod recursion_public_values;
pub mod septic_curve;
pub mod septic_digest;
pub mod septic_extension;
pub mod shape;
mod util;
mod verifier;
mod word;
pub use chip::*;
pub use debug::{debug_constraints, debug_constraints_all_chips, DebugConstraintBuilder};
pub use folder::*;
pub use logup_gkr::*;
pub use lookup::*;
pub use machine::*;
pub use record::*;
pub use recursion_public_values::{
    RecursionPublicValues, NUM_PV_ELMS_TO_HASH, PV_DIGEST_NUM_WORDS,
    RECURSION_PUBLIC_VALUES_COL_MAP, RECURSIVE_PROOF_NUM_PV_ELTS,
};
pub use util::*;
pub use verifier::*;
pub use word::*;
