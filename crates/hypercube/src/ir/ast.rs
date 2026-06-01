use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
};

use serde::{Deserialize, Serialize};
use slop_algebra::{extension::BinomialExtensionField, ExtensionField, Field};

use crate::{
    air::{AirInteraction, InteractionScope},
    ir::{Attribute, BinOp, ExprExtRef, ExprRef, FuncDecl, IrVar, OpExpr, Shape},
    InteractionKind,
};

use sp1_primitives::SP1Field;
type F = SP1Field;
type EF = BinomialExtensionField<SP1Field, 4>;

type AstType = Ast<ExprRef<F>, ExprExtRef<EF>>;

/// This should only be used under two scenarios:
/// 1. In the `SP1OperationBuilder` macro.
/// 2. When `SP1OperationBuilder` doesn't do its job and you need to implement `SP1Operation`
///    manually.
pub static GLOBAL_AST: LazyLock<Arc<Mutex<AstType>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Ast::new())));

/// Ast for the constraint compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ast<Expr, ExprExt> {
    assignments: Vec<usize>,
    ext_assignments: Vec<usize>,
    operations: Vec<OpExpr<Expr, ExprExt>>,
}

impl<F: Field, EF: ExtensionField<F>> Ast<ExprRef<F>, ExprExtRef<EF>> {
    /// Constructs a new AST.
    #[must_use]
    pub fn new() -> Self {
        Self { assignments: vec![], ext_assignments: vec![], operations: vec![] }
    }

    /// Allocate a new [`ExprRef`] and assign the result of the **next** operation
    /// to it.
    ///
    /// In practice, this usually means after calling [`Self::alloc`] you would have to push an
    /// [`OpExpr`]. For example, when `a = b + c`, call [`Self::alloc`] to allocate the LHS, and
    /// then push the [`OpExpr`] representing `b + c` to `self.operations`.
    pub fn alloc(&mut self) -> ExprRef<F> {
        let id = self.assignments.len();
        self.assignments.push(self.operations.len());
        ExprRef::Expr(id)
    }

    /// Allocate an array of [`ExprRef`] of constant size using [`Self::alloc`] and assign all of
    /// them to the **next** operation.
    pub fn alloc_array<const N: usize>(&mut self) -> [ExprRef<F>; N] {
        core::array::from_fn(|_| self.alloc())
    }

    /// Push an assignment operation.
    pub fn assign(&mut self, a: ExprRef<F>, b: ExprRef<F>) {
        let op = OpExpr::Assign(a, b);
        self.operations.push(op);
    }

    /// Same as [`Self::alloc`] but for [`ExprExtRef`]
    pub fn alloc_ext(&mut self) -> ExprExtRef<EF> {
        let id = self.ext_assignments.len();
        self.ext_assignments.push(self.operations.len());
        ExprExtRef::Expr(id)
    }

    /// Push an operation that asserts [`ExprRef`] x is zero.
    pub fn assert_zero(&mut self, x: ExprRef<F>) {
        let op = OpExpr::AssertZero(x);
        self.operations.push(op);
    }

    /// Same for [`Self::assert_zero`] but for [`ExprExtRef`].
    pub fn assert_ext_zero(&mut self, x: ExprExtRef<EF>) {
        let op = OpExpr::AssertExtZero(x);
        self.operations.push(op);
    }

    /// Records a binary operation and returns a new [`ExprRef`] that represents the result of this
    /// operation.
    pub fn bin_op(&mut self, op: BinOp, a: ExprRef<F>, b: ExprRef<F>) -> ExprRef<F> {
        let result = self.alloc();
        let op = OpExpr::BinOp(op, result, a, b);
        self.operations.push(op);
        result
    }

    /// Same with [`Self::bin_op`] but specifically for negation.
    pub fn negate(&mut self, a: ExprRef<F>) -> ExprRef<F> {
        let result = self.alloc();
        let op = OpExpr::Neg(result, a);
        self.operations.push(op);
        result
    }

    /// Same with [`Self::bin_op`] but for [`ExprExtRef`].
    pub fn bin_op_ext(
        &mut self,
        op: BinOp,
        a: ExprExtRef<EF>,
        b: ExprExtRef<EF>,
    ) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        let op = OpExpr::BinOpExt(op, result, a, b);
        self.operations.push(op);
        result
    }

    /// Same with [`Self::bin_op`] but for [`ExprExtRef`] and [`ExprRef`].
    pub fn bin_op_base_ext(
        &mut self,
        op: BinOp,
        a: ExprExtRef<EF>,
        b: ExprRef<F>,
    ) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        let op = OpExpr::BinOpBaseExt(op, result, a, b);
        self.operations.push(op);
        result
    }

    /// Same with [`Self::neg`] but for [`ExprExtRef`]
    pub fn neg_ext(&mut self, a: ExprExtRef<EF>) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        let op = OpExpr::NegExt(result, a);
        self.operations.push(op);
        result
    }

    /// Get an [`ExprExtRef`] from [`ExprRef`]
    pub fn ext_from_base(&mut self, a: ExprRef<F>) -> ExprExtRef<EF> {
        let result = self.alloc_ext();
        let op = OpExpr::ExtFromBase(result, a);
        self.operations.push(op);
        result
    }

    /// Records a send [`AirInteraction`]
    pub fn send(&mut self, message: AirInteraction<ExprRef<F>>, scope: InteractionScope) {
        let op = OpExpr::Send(message, scope);
        self.operations.push(op);
    }

    /// Records a receive [`AirInteraction`]
    pub fn receive(&mut self, message: AirInteraction<ExprRef<F>>, scope: InteractionScope) {
        let op = OpExpr::Receive(message, scope);
        self.operations.push(op);
    }

    /// A [String] of all the operations with [prefix] padding in the front.
    #[must_use]
    pub fn to_string_pretty(&self, prefix: &str) -> String {
        let mut s = String::new();
        for op in &self.operations {
            s.push_str(&format!("{prefix}{op}\n"));
        }
        s
    }

    /// Records an operation that represents a function call.
    pub fn call_operation(
        &mut self,
        name: String,
        inputs: Vec<(String, Attribute, Shape<ExprRef<F>, ExprExtRef<EF>>)>,
        output: Shape<ExprRef<F>, ExprExtRef<EF>>,
    ) {
        let func = FuncDecl::new(name, inputs, output);
        let op = OpExpr::Call(func);
        self.operations.push(op);
    }

    /// Go through the AST and returns a tuple that contains:
    /// 1. All the evaluation steps and function calls.
    /// 2. The field expressions asserted zero (`asserts`).
    /// 3. The bus sends/receives (`interactions`).
    /// 4. Number of calls.
    #[must_use]
    pub fn to_lean_components(
        &self,
        mapping: &HashMap<usize, String>,
    ) -> (Vec<String>, Vec<String>, Vec<String>, usize) {
        let mut steps: Vec<String> = Vec::default();
        let mut calls: usize = 0;
        let mut asserts: Vec<String> = Vec::default();
        let mut interactions: Vec<String> = Vec::default();

        for opexpr in &self.operations {
            match opexpr {
                OpExpr::AssertZero(expr) => {
                    asserts.push(expr.to_lean_string(mapping));
                }
                OpExpr::Neg(a, b) => {
                    steps.push(format!(
                        "let {} : F := -{}",
                        a.expr_to_lean_string(),
                        b.to_lean_string(mapping),
                    ));
                }
                OpExpr::BinOp(op, result, a, b) => {
                    let result_str = result.expr_to_lean_string();
                    let a_str = a.to_lean_string(mapping);
                    let b_str = b.to_lean_string(mapping);
                    match op {
                        BinOp::Add => {
                            steps.push(format!("let {result_str} : F := {a_str} + {b_str}"));
                        }
                        BinOp::Sub => {
                            steps.push(format!("let {result_str} : F := {a_str} - {b_str}"));
                        }
                        BinOp::Mul => {
                            steps.push(format!("let {result_str} : F := {a_str} * {b_str}"));
                        }
                    }
                }
                OpExpr::Send(interaction, _) => match interaction.kind {
                    InteractionKind::Byte
                    | InteractionKind::State
                    | InteractionKind::Memory
                    | InteractionKind::Program => {
                        interactions.push(format!(
                            "⟨.send, {}, {}⟩",
                            interaction.to_lean_string(mapping),
                            interaction.multiplicity.to_lean_string(mapping)
                        ));
                    }
                    _ => {}
                },
                OpExpr::Receive(interaction, _) => match interaction.kind {
                    InteractionKind::Byte
                    | InteractionKind::State
                    | InteractionKind::Memory
                    | InteractionKind::Program => {
                        interactions.push(format!(
                            "⟨.receive, {}, {}⟩",
                            interaction.to_lean_string(mapping),
                            interaction.multiplicity.to_lean_string(mapping),
                        ));
                    }
                    _ => {}
                },
                OpExpr::Call(decl) => {
                    // Build the call expression `<name>.constraints <inputs…>`.
                    let mut call = format!("{}.constraints", decl.name);
                    for input in &decl.input {
                        call.push(' ');
                        call.push_str(&input.2.to_lean_constructor(mapping));
                    }

                    match decl.output {
                        Shape::Unit => {
                            steps.push(format!(
                                "let CS{calls} : SP1Constraints F := {call}"
                            ));
                        }
                        // A constraints-returning sub-operation yields `(output, SP1Constraints)`.
                        // Bind the pair to a temporary, then project the output value by index
                        // (`tmp.1[k]`) and the constraints (`tmp.2`). A structural
                        // `let ⟨⟨[..]⟩, _⟩` destructure of the `Vector` output does not elaborate,
                        // so we avoid it.
                        Shape::Expr(ref expr) => {
                            let tmp = format!("__call{calls}");
                            steps.push(format!("let {tmp} := {call}"));
                            steps.push(format!(
                                "let {} := {tmp}.1",
                                expr.to_lean_string(&HashMap::default())
                            ));
                            steps.push(format!(
                                "let CS{calls} : SP1Constraints F := {tmp}.2"
                            ));
                        }
                        _ => {
                            let tmp = format!("__call{calls}");
                            steps.push(format!("let {tmp} := {call}"));
                            for (k, leaf) in decl.output.output_leaves().iter().enumerate() {
                                steps.push(format!("let {leaf} := {tmp}.1[{k}]"));
                            }
                            steps.push(format!(
                                "let CS{calls} : SP1Constraints F := {tmp}.2"
                            ));
                        }
                    }

                    calls += 1;
                }
                OpExpr::Assign(ExprRef::IrVar(IrVar::OutputArg(_)), _) => {
                    // Output(x) are specifically ignored
                }
                _ => todo!(),
            }
        }

        (steps, asserts, interactions, calls)
    }
}

impl<F: Field, EF: ExtensionField<F>> Default for Ast<ExprRef<F>, ExprExtRef<EF>> {
    fn default() -> Self {
        Self::new()
    }
}
