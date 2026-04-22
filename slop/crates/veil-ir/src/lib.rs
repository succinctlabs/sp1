//! Typed IR for the VEIL verifier DSL.
//!
//! A verifier function written generically over the trait surface in
//! `slop_veil::compiler` (`ConstraintCtx`, `ReadingCtx`) can be instantiated
//! with [`builder::IrBuilder`] to produce a [`Program`], the canonical
//! semantic artifact. Multiple backends consume the program:
//!
//! - [`interp::run_native`] — eager native interpreter, no PCS.
//! - `zk_lower` (stub; future PR) — replay through `slop_veil`'s ZK
//!   verifier context.
//! - Future Lean pretty-printer — target for formal verification.

#![allow(clippy::disallowed_types)]

mod ir;
mod walk;

pub mod builder;
pub mod interp;
pub mod validate;
pub mod zk_lower;

pub use ir::{Expr, ExprArena, ExprId, ExprKind, ExprType, OracleId, Program, Stmt, VarId};
pub use walk::walk_expr_dag;
