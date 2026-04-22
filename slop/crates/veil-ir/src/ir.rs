//! Core IR types: typed expressions, statements, arena, and programs.

use std::collections::HashMap;
use std::hash::Hash;

/// Type tag carried on every arena expression.
///
/// Distinguishes extension-field-typed expressions from Fiat-Shamir challenges.
/// The `Ext` / `Challenge` distinction matches the `ConstraintCtx::Expr` vs
/// `ConstraintCtx::Challenge` associated types in `slop_veil::compiler`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExprType {
    Ext,
    Challenge,
}

/// Index into an [`ExprArena`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExprId(pub u32);

/// Identifier for a transcript-read or sampled scalar variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarId(pub u32);

/// Identifier for an MLE oracle read from the transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OracleId(pub u32);

/// One node in an [`ExprArena`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExprKind<E> {
    /// Extension-field constant. Stored inline; the arena is generic over `E`.
    ConstExt(E),
    /// A transcript-read variable (tagged `Ext`).
    Var(VarId),
    /// A sampled Fiat-Shamir challenge (tagged `Challenge`).
    Challenge(VarId),
    Add(ExprId, ExprId),
    Sub(ExprId, ExprId),
    Mul(ExprId, ExprId),
    Neg(ExprId),
}

/// A typed arena expression: a [`ExprKind`] plus a type tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Expr<E> {
    pub ty: ExprType,
    pub kind: ExprKind<E>,
}

/// Hash-consed arena of expressions.
///
/// `intern` is the only way to add nodes. Structurally equal expressions
/// receive the same [`ExprId`], giving common-subexpression elimination for
/// free.
pub struct ExprArena<E> {
    nodes: Vec<Expr<E>>,
    dedup: HashMap<Expr<E>, ExprId>,
}

impl<E> Default for ExprArena<E> {
    fn default() -> Self {
        Self { nodes: Vec::new(), dedup: HashMap::new() }
    }
}

impl<E> ExprArena<E> {
    pub fn get(&self, id: ExprId) -> &Expr<E> {
        &self.nodes[id.0 as usize]
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (ExprId, &Expr<E>)> {
        self.nodes.iter().enumerate().map(|(i, e)| (ExprId(i as u32), e))
    }
}

impl<E: Clone + Hash + Eq> ExprArena<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, expr: Expr<E>) -> ExprId {
        if let Some(&id) = self.dedup.get(&expr) {
            return id;
        }
        let id = ExprId(self.nodes.len() as u32);
        self.nodes.push(expr.clone());
        self.dedup.insert(expr, id);
        id
    }
}

/// One statement in a [`Program`].
///
/// Statements execute in order and carry the side-effecting part of the
/// verifier: transcript reads, challenge samples, PCS commitments, and
/// constraint assertions.
#[derive(Clone, Debug)]
pub enum Stmt {
    /// Read `count` extension-field elements from the transcript.
    /// Bound to variables `start`, `start + 1`, …, `start + count - 1`.
    ReadTranscript { start: VarId, count: u32 },
    /// Sample a Fiat-Shamir challenge. Bound to `dst`.
    Sample { dst: VarId },
    /// Read a PCS commitment from the transcript. Bound to `dst`.
    ReadOracle { dst: OracleId, num_encoding_variables: u32, log_num_polynomials: u32 },
    /// Require `⟦expr⟧ = 0`.
    AssertZero(ExprId),
    /// Require `⟦a⟧ · ⟦b⟧ = ⟦c⟧`. Preferred over `AssertZero(a*b - c)` to
    /// avoid materializing the product in backends that can constrain
    /// multiplication directly.
    AssertProduct(ExprId, ExprId, ExprId),
    /// Batched MLE eval claim: for each `(oracle, eval)` in `claims`, require
    /// that the committed polynomial at `oracle` evaluates to `⟦eval⟧` at
    /// the shared `point`.
    AssertMleMultiEval { claims: Vec<(OracleId, ExprId)>, point: Vec<ExprId> },
}

/// Canonical IR artifact produced by [`crate::builder::IrBuilder`].
///
/// `Program` is cheap to clone (expressions live in the arena; statements
/// hold only small ids), and is the input to every backend.
pub struct Program<E> {
    pub stmts: Vec<Stmt>,
    pub exprs: ExprArena<E>,
    pub num_vars: u32,
    pub num_oracles: u32,
}

impl<E> Program<E> {
    /// Returns the expected transcript length in scalars, counting one per
    /// `Var` binding. Challenges are sampled, not read, and do not count.
    pub fn transcript_len(&self) -> usize {
        self.stmts
            .iter()
            .map(|s| match s {
                Stmt::ReadTranscript { count, .. } => *count as usize,
                _ => 0,
            })
            .sum()
    }

    /// Returns the number of `ReadOracle` statements.
    pub fn oracle_count(&self) -> usize {
        self.stmts.iter().filter(|s| matches!(s, Stmt::ReadOracle { .. })).count()
    }
}
