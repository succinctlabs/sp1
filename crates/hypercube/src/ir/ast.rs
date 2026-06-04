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

/// Identifier of a generated `let` binding, used for per-function dead-code elimination: each
/// emitted def (`asserts` / `interactions` / `value`) keeps only the bindings reachable from its
/// return expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindId {
    /// An SSA `E<n>` value (`n` = the `ExprRef::Expr` index).
    Expr(usize),
    /// A sub-call's value binding `__call<n>_v` (`n` = the call index within this body).
    CallVal(usize),
}

/// A candidate `let` binding (its `<lhs> := <rhs>` text, without the leading `let`) together with
/// the `BindId`s it reads — the edges of the dependency DAG that DCE walks.
#[derive(Debug, Clone)]
pub struct LeanBinding {
    /// What this binding defines.
    pub id: BindId,
    /// The binding text, e.g. `E5 : F := E4 * E3` or `__call0_v := Foo.value …`. No leading `let`.
    pub text: String,
    /// The bindings this one reads.
    pub deps: Vec<BindId>,
}

/// A sub-operation call term in an append chain (`Foo.asserts <args>` for the `asserts` def,
/// `Foo.interactions <args>` for the `interactions` def), plus the `BindId`s its `<args>` read.
#[derive(Debug, Clone)]
pub struct SubCallTerm {
    /// The `<name>.asserts <args>` / `<name>.interactions <args>` text.
    pub text: String,
    /// The bindings the `<args>` read.
    pub deps: Vec<BindId>,
}

/// The per-function-renderable material of one operation/chip body. The caller renders each def
/// (`asserts` / `interactions` / `value`) by selecting the subset of `bindings` reachable from
/// that def's roots (its own-list deps + sub-call arg deps, or the value constructor's refs).
#[derive(Debug, Clone)]
pub struct LeanComponents {
    /// All candidate `let` bindings, in program (topological) order.
    pub bindings: Vec<LeanBinding>,
    /// Own field asserts (each `= 0`), with their dep ids.
    pub asserts: Vec<(String, Vec<BindId>)>,
    /// Own bus interactions, with their dep ids.
    pub interactions: Vec<(String, Vec<BindId>)>,
    /// Sub-operation `.asserts <args>` terms, in call order.
    pub sub_asserts: Vec<SubCallTerm>,
    /// Sub-operation `.interactions <args>` terms, in call order.
    pub sub_interactions: Vec<SubCallTerm>,
    /// Per **byte** interaction, the Clean-native channel-call form (`byteChannel.gatedReceive …`)
    /// the circuit `main` emits, with its dep ids. Only byte interactions contribute here (the
    /// `State`/`Memory`/`Program` buses are emitted as `main` calls only once those channels land),
    /// so `channel_calls.len()` equals the number of byte interactions — the circuit emitter checks
    /// this matches `interactions.len()` to confirm an op is byte-bus-only before emitting `main`.
    pub channel_calls: Vec<(String, Vec<BindId>)>,
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

    /// Walk the AST and return the [`LeanComponents`] from which the caller renders the operation's
    /// (or chip's) separate `asserts` / `interactions` / `value` defs.
    ///
    /// Each arithmetic/`let` step becomes a [`LeanBinding`] carrying the `BindId`s it reads; each
    /// `AssertZero` / `Send`·`Receive` becomes an own-list entry with its deps; each `Call` becomes
    /// a `Foo.asserts <args>` / `Foo.interactions <args>` [`SubCallTerm`] (and, for a value-returning
    /// sub-op, a `__call<n>_v := Foo.value <args>` header binding plus its output-leaf bindings).
    /// The caller selects, per def, the bindings reachable from that def's roots — so no def carries
    /// a `let` it does not use.
    #[must_use]
    pub fn to_lean_components(&self, mapping: &HashMap<usize, String>) -> LeanComponents {
        let mut bindings: Vec<LeanBinding> = Vec::default();
        let mut asserts: Vec<(String, Vec<BindId>)> = Vec::default();
        let mut interactions: Vec<(String, Vec<BindId>)> = Vec::default();
        let mut sub_asserts: Vec<SubCallTerm> = Vec::default();
        let mut sub_interactions: Vec<SubCallTerm> = Vec::default();
        let mut channel_calls: Vec<(String, Vec<BindId>)> = Vec::default();
        let mut calls: usize = 0;

        for opexpr in &self.operations {
            match opexpr {
                OpExpr::AssertZero(expr) => {
                    asserts.push((expr.to_lean_string(mapping), refs_vec(&[*expr])));
                }
                OpExpr::Neg(a, b) => {
                    bindings.push(LeanBinding {
                        id: bind_id_of(a),
                        text: format!("{} : F := -{}", a.expr_to_lean_string(), b.to_lean_string(mapping)),
                        deps: refs_vec(&[*b]),
                    });
                }
                OpExpr::BinOp(op, result, a, b) => {
                    let result_str = result.expr_to_lean_string();
                    let a_str = a.to_lean_string(mapping);
                    let b_str = b.to_lean_string(mapping);
                    let text = match op {
                        BinOp::Add => format!("{result_str} : F := {a_str} + {b_str}"),
                        BinOp::Sub => format!("{result_str} : F := {a_str} - {b_str}"),
                        BinOp::Mul => format!("{result_str} : F := {a_str} * {b_str}"),
                    };
                    bindings.push(LeanBinding { id: bind_id_of(result), text, deps: refs_vec(&[*a, *b]) });
                }
                OpExpr::Send(interaction, _) => match interaction.kind {
                    InteractionKind::Byte
                    | InteractionKind::State
                    | InteractionKind::Memory
                    | InteractionKind::Program => {
                        interactions.push((
                            format!(
                                "⟨.send, {}, {}⟩",
                                interaction.to_lean_string(mapping),
                                interaction.multiplicity.to_lean_string(mapping)
                            ),
                            refs_of_interaction(interaction),
                        ));
                        if matches!(interaction.kind, InteractionKind::Byte) {
                            channel_calls.push((
                                byte_channel_call(interaction, mapping),
                                refs_of_interaction(interaction),
                            ));
                        }
                    }
                    _ => {}
                },
                OpExpr::Receive(interaction, _) => match interaction.kind {
                    InteractionKind::Byte
                    | InteractionKind::State
                    | InteractionKind::Memory
                    | InteractionKind::Program => {
                        interactions.push((
                            format!(
                                "⟨.receive, {}, {}⟩",
                                interaction.to_lean_string(mapping),
                                interaction.multiplicity.to_lean_string(mapping),
                            ),
                            refs_of_interaction(interaction),
                        ));
                        if matches!(interaction.kind, InteractionKind::Byte) {
                            channel_calls.push((
                                byte_channel_call(interaction, mapping),
                                refs_of_interaction(interaction),
                            ));
                        }
                    }
                    _ => {}
                },
                OpExpr::Call(decl) => {
                    // Build the trailing ` <inputs…>` shared by `.asserts`/`.interactions`/`.value`,
                    // along with the bindings those inputs read (drives DCE of each call term).
                    let mut args = String::new();
                    let mut arg_deps: Vec<BindId> = Vec::new();
                    for input in &decl.input {
                        args.push(' ');
                        args.push_str(&input.2.to_lean_constructor(mapping));
                        refs_of_shape(&input.2, &mut arg_deps);
                    }

                    sub_asserts.push(SubCallTerm {
                        text: format!("{}.asserts{args}", decl.name),
                        deps: arg_deps.clone(),
                    });
                    sub_interactions.push(SubCallTerm {
                        text: format!("{}.interactions{args}", decl.name),
                        deps: arg_deps.clone(),
                    });

                    // A value-returning sub-op also contributes a `value` call; bind it once
                    // (`__call<n>_v`) and project the output by index (`__call<n>_v[k]`) — a
                    // structural `⟨⟨[..]⟩, _⟩` destructure of the `Vector` does not elaborate.
                    // Unit sub-ops have no value (only the two call terms above).
                    match decl.output {
                        Shape::Unit => {}
                        Shape::Expr(ref expr) => {
                            bindings.push(LeanBinding {
                                id: BindId::CallVal(calls),
                                text: format!("__call{calls}_v := {}.value{args}", decl.name),
                                deps: arg_deps.clone(),
                            });
                            bindings.push(LeanBinding {
                                id: bind_id_of(expr),
                                text: format!("{} := __call{calls}_v", expr.expr_to_lean_string()),
                                deps: vec![BindId::CallVal(calls)],
                            });
                        }
                        _ => {
                            bindings.push(LeanBinding {
                                id: BindId::CallVal(calls),
                                text: format!("__call{calls}_v := {}.value{args}", decl.name),
                                deps: arg_deps.clone(),
                            });
                            for (k, leaf) in decl.output.output_leaf_refs().iter().enumerate() {
                                bindings.push(LeanBinding {
                                    id: bind_id_of(leaf),
                                    text: format!("{} := __call{calls}_v[{k}]", leaf.expr_to_lean_string()),
                                    deps: vec![BindId::CallVal(calls)],
                                });
                            }
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

        LeanComponents {
            bindings,
            asserts,
            interactions,
            sub_asserts,
            sub_interactions,
            channel_calls,
        }
    }
}

/// The Clean-native channel-call form of one **byte** interaction — the statement the circuit `main`
/// emits in place of the generic `⟨.send, .byte …, mult⟩` list entry. SP1's `send_byte(op, a, b, c)`
/// with multiplicity `g` becomes `byteChannel.gatedReceive g ⟨op, a, b', c⟩` (a *pull* of the
/// preprocessed `ByteChip`; the sign flip is the send/receive duality, `Foundations/Channels.lean`).
/// The looked-up value `a` is passed **raw**, multiplicity-gated by `g` on `toRawGated` — faithful to
/// SP1's `send_byte(…, is_real)`, whose LogUp term is `g / fingerprint(values)`, so a padding row
/// (`g = 0`) drops out of the sum entirely and its values are unconstrained (no `g * a` fold). The
/// bit-width column `b`, when a literal, is rendered `Expression.const ((b:ℕ):ZMod p)` so it matches
/// `byteRowSpec_range`'s `((n:ℕ):ZMod p)` shape (`Foundations/ByteTable.lean`).
fn byte_channel_call<F: Field>(
    it: &AirInteraction<ExprRef<F>>,
    mapping: &HashMap<usize, String>,
) -> String {
    debug_assert_eq!(it.values.len(), 4, "a byte interaction has arity 4 (op a b c)");
    let op = it.values[0].to_lean_string(mapping);
    let a = it.values[1].to_lean_string(mapping);
    let b = it.values[2].to_lean_string(mapping);
    let c = it.values[3].to_lean_string(mapping);
    let gate = it.multiplicity.to_lean_string(mapping);
    // A literal bit-width column is cast `((b:ℕ):ZMod p)` (the `byteRowSpec_range` shape); a non-literal
    // (a real column) is already an `Expression` and is emitted bare.
    let b_field = if !b.is_empty() && b.bytes().all(|ch| ch.is_ascii_digit()) {
        format!("Expression.const (({b} : ℕ) : ZMod p)")
    } else {
        b
    };
    format!(
        "byteChannel.gatedReceive {gate} \
         (⟨{op}, {a}, {b_field}, {c}⟩ : ByteRow (Expression (ZMod p)))"
    )
}

/// The `BindId` read by a single expression reference; only an SSA `Expr(i)` is a binding (leaves
/// like `Main`/`Constant`/`InputArg` have no in-body dependency).
fn ref_of_expr<F: Field>(e: &ExprRef<F>) -> Option<BindId> {
    match e {
        ExprRef::Expr(i) => Some(BindId::Expr(*i)),
        _ => None,
    }
}

/// The `BindId` a generated `let` binding defines (its LHS is always an SSA `Expr`).
fn bind_id_of<F: Field>(e: &ExprRef<F>) -> BindId {
    match e {
        ExprRef::Expr(i) => BindId::Expr(*i),
        _ => unreachable!("the LHS of a generated `let` binding is always an `Expr`"),
    }
}

/// The `BindId`s read by a list of expressions.
fn refs_vec<F: Field>(exprs: &[ExprRef<F>]) -> Vec<BindId> {
    exprs.iter().filter_map(ref_of_expr).collect()
}

/// Collect every SSA `Expr` leaf appearing in a shape (a sub-call argument) as the bindings that
/// argument reads. `pub` so the chip/operation emitter can compute a `value` def's roots from the
/// output shape.
pub fn refs_of_shape<F: Field, EF: ExtensionField<F>>(
    shape: &Shape<ExprRef<F>, ExprExtRef<EF>>,
    out: &mut Vec<BindId>,
) {
    match shape {
        Shape::Expr(e) => {
            if let Some(b) = ref_of_expr(e) {
                out.push(b);
            }
        }
        Shape::Word(word) => {
            for e in word {
                if let Some(b) = ref_of_expr(e) {
                    out.push(b);
                }
            }
        }
        Shape::Array(vals) => {
            for v in vals {
                refs_of_shape(v, out);
            }
        }
        Shape::Struct(_, fields) => {
            for (_, f) in fields {
                refs_of_shape(f, out);
            }
        }
        Shape::Unit | Shape::ExprExt(_) => {}
    }
}

/// The `BindId`s read by a bus interaction (its values and multiplicity).
fn refs_of_interaction<F: Field>(it: &AirInteraction<ExprRef<F>>) -> Vec<BindId> {
    let mut out: Vec<BindId> = it.values.iter().filter_map(ref_of_expr).collect();
    if let Some(b) = ref_of_expr(&it.multiplicity) {
        out.push(b);
    }
    out
}

impl<F: Field, EF: ExtensionField<F>> Default for Ast<ExprRef<F>, ExprExtRef<EF>> {
    fn default() -> Self {
        Self::new()
    }
}
