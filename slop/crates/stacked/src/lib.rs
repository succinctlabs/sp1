#![allow(clippy::disallowed_types)]
//! API for stacked multilinear polynomial commitment schemes.
//!
//!
//! For any multilinear PCS that can commit to batches of matrices of the same height (considering
//! the columns of those matrices as evaluations of multilinear polynomials on the Boolean
//! hypercube), and then prove joint evaluations of those multililiner polynomials at the same
//! point, this module provides functionality that can commit to heterogeneous batches of matrices
//! (considering that batch as a single mutlilinear polynomial in many variables), and then prove
//! evaluations of that multilinear polynomial at a point.
//!
//! This is implemented by making a virtual vector consisting of the concatenation of all of the
//! data in the matrices in the batch, splitting that vector up into vectors of a prescribed size,
//! and then using the underlying PCS to commit to and prove evaluations of those vectors. The
//! verifier then computes the expected multilinear evaluation of the larger vector by using a
//! multilinear evaluation algorithm in a smaller number of variables). This is essentially the
//! the interleaving algorithm of `Ligero`(https://eprint.iacr.org/2022/1608).

mod fixed_rate;
mod prover;
mod stacked_oracle;
mod verifier;

pub use fixed_rate::*;
pub use prover::*;
pub use stacked_oracle::*;
pub use verifier::*;
