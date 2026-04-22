//! Type-correctness validation for a [`Program`].
//!
//! Walks the arena and confirms the per-node [`ExprType`] tags are
//! consistent. `IrBuilder` constructs only well-typed handles by
//! construction, so this pass primarily catches bugs in the builder and
//! in any future `Program`-to-`Program` transforms.

use std::hash::Hash;

use thiserror::Error;

use crate::{ExprId, ExprKind, ExprType, Program, Stmt, VarId};

#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("expr id {0:?} references a node outside the arena")]
    DanglingExpr(ExprId),
    #[error("mismatched operand types in {op}: lhs={lhs:?}, rhs={rhs:?}")]
    MismatchedOperands { op: &'static str, lhs: ExprType, rhs: ExprType },
    #[error("Neg operand has unexpected type {0:?}")]
    BadNegOperand(ExprType),
    #[error("AssertZero target has non-Ext type {0:?}")]
    AssertZeroNonExt(ExprType),
    #[error("AssertProduct operand #{idx} has non-Ext type {ty:?}")]
    AssertProductNonExt { idx: u8, ty: ExprType },
    #[error("AssertMleMultiEval eval/point node has non-Ext type {0:?}")]
    MleEvalNonExt(ExprType),
    #[error("statement references undefined VarId {0:?}")]
    UndefinedVar(VarId),
}

pub fn validate<E>(program: &Program<E>) -> Result<(), ValidateError>
where
    E: Clone + Hash + Eq,
{
    // First, check all statement-level expr ids are in-range and that the
    // emitted arena nodes are themselves locally well-typed.
    for (id, expr) in program.exprs.iter() {
        match &expr.kind {
            ExprKind::ConstExt(_) => {
                require(expr.ty == ExprType::Ext, ValidateError::AssertZeroNonExt(expr.ty))?;
            }
            ExprKind::Var(_) => {
                require(expr.ty == ExprType::Ext, ValidateError::AssertZeroNonExt(expr.ty))?;
            }
            ExprKind::Challenge(_) => {
                require(expr.ty == ExprType::Challenge, ValidateError::AssertZeroNonExt(expr.ty))?;
            }
            ExprKind::Add(a, b) | ExprKind::Sub(a, b) | ExprKind::Mul(a, b) => {
                check_in_bounds(*a, program)?;
                check_in_bounds(*b, program)?;
                // Operands may be Ext or Challenge; result is always Ext
                // (the builder emits Ext-typed arithmetic).
                require(expr.ty == ExprType::Ext, ValidateError::AssertZeroNonExt(expr.ty))?;
                // We don't require operand types to be identical: a
                // Challenge handle is a valid operand to Ext-valued Add/Mul,
                // matching the `Expr: Algebra<Challenge>` trait bound.
            }
            ExprKind::Neg(a) => {
                check_in_bounds(*a, program)?;
                // result type matches operand (preserved by builder)
                let op_ty = program.exprs.get(*a).ty;
                require(expr.ty == op_ty, ValidateError::BadNegOperand(op_ty))?;
            }
        }
        let _ = id;
    }

    // Now check statements reference in-range exprs/vars/oracles.
    for stmt in &program.stmts {
        match stmt {
            Stmt::ReadTranscript { start, count } => {
                require(
                    start.0 + count <= program.num_vars,
                    ValidateError::UndefinedVar(VarId(start.0 + count - 1)),
                )?;
            }
            Stmt::Sample { dst } => {
                require(dst.0 < program.num_vars, ValidateError::UndefinedVar(*dst))?;
            }
            Stmt::ReadOracle { dst, .. } => {
                require(dst.0 < program.num_oracles, ValidateError::UndefinedVar(VarId(dst.0)))?;
            }
            Stmt::AssertZero(e) => {
                check_in_bounds(*e, program)?;
                let ty = program.exprs.get(*e).ty;
                require(ty == ExprType::Ext, ValidateError::AssertZeroNonExt(ty))?;
            }
            Stmt::AssertProduct(a, b, c) => {
                for (idx, e) in [a, b, c].iter().enumerate() {
                    check_in_bounds(**e, program)?;
                    let ty = program.exprs.get(**e).ty;
                    require(
                        ty == ExprType::Ext,
                        ValidateError::AssertProductNonExt { idx: idx as u8, ty },
                    )?;
                }
            }
            Stmt::AssertMleMultiEval { claims, point } => {
                for (_oracle, eval) in claims {
                    check_in_bounds(*eval, program)?;
                    let ty = program.exprs.get(*eval).ty;
                    require(ty == ExprType::Ext, ValidateError::MleEvalNonExt(ty))?;
                }
                for p in point {
                    check_in_bounds(*p, program)?;
                    // Point components are Challenge-typed at the trait level;
                    // the builder emits them as Challenge-tagged arena nodes.
                }
            }
        }
    }
    Ok(())
}

fn check_in_bounds<E>(id: ExprId, program: &Program<E>) -> Result<(), ValidateError> {
    if (id.0 as usize) < program.exprs.len() {
        Ok(())
    } else {
        Err(ValidateError::DanglingExpr(id))
    }
}

fn require(cond: bool, err: ValidateError) -> Result<(), ValidateError> {
    if cond {
        Ok(())
    } else {
        Err(err)
    }
}
