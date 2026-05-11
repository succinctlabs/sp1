use std::{borrow::Borrow, collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use slop_algebra::Field;

use crate::ir::{FuncCtx, IrVar};

/// The `AB::Expr` of the constraint compiler. Note that for the constraint
/// compiler, this is also `AB::Var`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExprRef<F> {
    /// An [`IrVar`], usually this comes from the chip/inputs.
    IrVar(IrVar<F>),
    /// An expression where its value `i` means this expression represents the
    /// value of the i-th assignment. For the constraint compiler, since it
    /// uses an SSA-style IR, `i` also means this expression represents the
    /// result of the i-th computation.
    Expr(usize),
}

impl<F: Field> ExprRef<F> {
    /// An expression representing a variable from public inputs.
    #[must_use]
    pub fn public(index: usize) -> Self {
        ExprRef::IrVar(IrVar::Public(index))
    }

    /// An expression representing a variable from preprocessed trace.
    #[must_use]
    pub fn preprocessed(index: usize) -> Self {
        ExprRef::IrVar(IrVar::Preprocessed(index))
    }

    /// An expression representing a variable from main trace.
    #[must_use]
    pub fn main(index: usize) -> Self {
        ExprRef::IrVar(IrVar::Main(index))
    }

    /// An expression representing a constant value.
    pub fn constant(value: F) -> Self {
        ExprRef::IrVar(IrVar::Constant(value))
    }

    /// An expression representing a variable from input arguments.
    pub fn input_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.input_idx;
        ctx.input_idx += 1;
        ExprRef::IrVar(IrVar::InputArg(index))
    }

    /// Get a struct with input arguments.
    ///
    /// Given a sized struct that can be flattened to a slice of `Self`, produce a new struct of
    /// this type where all the fields are replaced with input arguments.
    pub fn input_from_struct<T>(ctx: &mut FuncCtx) -> T
    where
        T: Copy,
        [Self]: Borrow<T>,
    {
        let size = std::mem::size_of::<T>() / std::mem::size_of::<Self>();
        let values = (0..size).map(|_| Self::input_arg(ctx)).collect::<Vec<_>>();
        let value_ref: &T = values.as_slice().borrow();
        *value_ref
    }

    /// An expression representing a variable from output arguments.
    pub fn output_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.output_idx;
        ctx.output_idx += 1;
        ExprRef::IrVar(IrVar::OutputArg(index))
    }

    /// Get a struct with output arguments.
    ///
    /// Given a sized struct that can be flattened to a slice of `Self`, produce a new struct of
    /// this type where all the fields are replaced with output arguments.
    pub fn output_from_struct<T>(ctx: &mut FuncCtx) -> T
    where
        T: Copy,
        [Self]: Borrow<T>,
    {
        let size = std::mem::size_of::<T>() / std::mem::size_of::<Self>();
        let values = (0..size).map(|_| Self::output_arg(ctx)).collect::<Vec<_>>();
        let value_ref: &T = values.as_slice().borrow();
        *value_ref
    }

    /// Returns the value in Lean-syntax string
    pub fn to_lean_string(&self, input_mapping: &HashMap<usize, String>) -> String {
        match self {
            ExprRef::Expr(idx) => format!("E{idx}"),
            ExprRef::IrVar(IrVar::Main(idx)) => format!("Main[{idx}]"),
            ExprRef::IrVar(IrVar::Constant(idx)) => format!("{idx}"),
            ExprRef::IrVar(IrVar::InverseConstant { base, .. }) => {
                format!("(({base} : Fin KB)⁻¹)")
            }
            ExprRef::IrVar(IrVar::InputArg(idx)) => input_mapping.get(idx).unwrap().clone(),
            ExprRef::IrVar(IrVar::Public(idx)) => format!("public_value () {idx}"),
            _ => todo!(),
        }
    }

    /// Returns the value in Lean-syntax string, except that it must be an intermediate expression.
    ///
    /// Used for the LHS when assigning variables in steps
    pub fn expr_to_lean_string(&self) -> String {
        match self {
            ExprRef::Expr(idx) => format!("E{idx}"),
            _ => unimplemented!(),
        }
    }
}

impl<F: Field> Display for ExprRef<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprRef::IrVar(ir_var) => write!(f, "{ir_var}"),
            ExprRef::Expr(expr) => write!(f, "Expr({expr})"),
        }
    }
}

impl<F: Field> ExprRef<F> {
    /// Convert to Lean syntax
    pub fn to_lean(&self, is_operation: bool, input_mapping: &HashMap<usize, String>) -> String {
        match self {
            ExprRef::IrVar(var) => var.to_lean(is_operation, input_mapping),
            ExprRef::Expr(i) => format!("E{i}"),
        }
    }
}

/// The [`ExtensionField`] for the constraint compiler.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExprExtRef<EF> {
    /// A constant in the extension field.
    ExtConstant(EF),
    /// An expression where its value `i` means this expression represents the
    /// value of the i-th assignment. For the constraint compiler, since it
    /// uses an SSA-style IR, `i` also means this expression represents the
    /// result of the i-th computation.
    Expr(usize),
}

impl<EF: Field> ExprExtRef<EF> {
    /// An expression representing a variable from input arguments.
    pub fn input_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.input_idx;
        ctx.input_idx += 1;
        ExprExtRef::Expr(index)
    }

    /// An expression representing a variable from output arguments.
    pub fn output_arg(ctx: &mut FuncCtx) -> Self {
        let index = ctx.output_idx;
        ctx.output_idx += 1;
        ExprExtRef::Expr(index)
    }
}

impl<EF: Field> Display for ExprExtRef<EF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprExtRef::ExtConstant(ext_constant) => write!(f, "{ext_constant}"),
            ExprExtRef::Expr(expr) => write!(f, "ExprExt({expr})"),
        }
    }
}

impl<EF: Field> ExprExtRef<EF> {
    /// Convert to Lean syntax
    pub fn to_lean(&self, _is_operation: bool, _input_mapping: &HashMap<usize, String>) -> String {
        match self {
            ExprExtRef::ExtConstant(c) => format!("{c}"),
            ExprExtRef::Expr(i) => format!("EExt{i}"),
        }
    }
}
