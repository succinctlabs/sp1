//! Flattened-AST expression pool for the transparent verifier.
//!
//! Every operation on a verifier [`Expr`] either folds at construction (constant ⋆
//! constant → constant) or pushes one node into a shared pool and returns a fresh
//! [`Expr::Node`]. `verify()` walks the pool linearly (one pass, no recursion) to
//! evaluate claims.
//!
//! `Expr` is a two-variant enum: [`Expr::Const`] holds a bare field element off-pool;
//! [`Expr::Node`] holds a pool handle. Constants only ever live in `Expr` itself — the
//! pool never carries a standalone `Const` node. Binary pool nodes take [`Operand`]s
//! that are either a pool index or an inlined constant, so a mixed "Const ⋆ Node"
//! construction costs exactly one pool entry.

use std::{
    cell::RefCell,
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

use slop_algebra::{AbstractField, Field};

/// Operand of a binary [`ExprNode`]: either another pool entry or an inlined
/// constant.
#[derive(Clone, Copy, Debug)]
pub enum Operand<EF> {
    Node(usize),
    Const(EF),
}

/// A single node in the verifier's expression pool.
#[derive(Clone, Copy, Debug)]
pub enum ExprNode<EF> {
    /// A transcript element at `(group_idx, local_idx)` in the verifier's
    /// `Vec<Vec<EF>>` transcript.
    Var(usize, usize),
    Add(Operand<EF>, Operand<EF>),
    Sub(Operand<EF>, Operand<EF>),
    Mul(Operand<EF>, Operand<EF>),
}

/// Append-only pool of expression nodes. A node at index `i` may reference only
/// earlier indices (`< i`), which lets `verify()` evaluate in one linear pass.
#[derive(Clone, Default, Debug)]
pub struct ExpressionPool<EF> {
    nodes: Vec<ExprNode<EF>>,
}

impl<EF> ExpressionPool<EF> {
    /// Append a node and return its index.
    pub fn push(&mut self, node: ExprNode<EF>) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    pub fn nodes(&self) -> &[ExprNode<EF>] {
        &self.nodes
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A handle into an [`ExpressionPool`]: pool reference + node index.
#[derive(Clone)]
pub struct Element<EF> {
    pool: Rc<RefCell<ExpressionPool<EF>>>,
    idx: usize,
}

impl<EF> Debug for Element<EF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Element").field("idx", &self.idx).finish()
    }
}

impl<EF> Element<EF> {
    pub fn new(pool: Rc<RefCell<ExpressionPool<EF>>>, idx: usize) -> Self {
        Self { pool, idx }
    }

    pub fn idx(&self) -> usize {
        self.idx
    }

    pub fn pool(&self) -> &Rc<RefCell<ExpressionPool<EF>>> {
        &self.pool
    }
}

/// Verifier expression: either an inlined constant, or a handle into the pool.
#[derive(Clone)]
pub enum Expr<EF> {
    Const(EF),
    Node(Element<EF>),
}

impl<EF: Debug> Debug for Expr<EF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Const(c) => write!(f, "Const({c:?})"),
            Expr::Node(e) => Debug::fmt(e, f),
        }
    }
}

impl<EF: Default> Default for Expr<EF> {
    fn default() -> Self {
        Expr::Const(EF::default())
    }
}

impl<EF> From<EF> for Expr<EF> {
    fn from(value: EF) -> Self {
        Expr::Const(value)
    }
}

// ============================================================================
// Operator impls. The pattern everywhere:
//   - (Const, Const) → fold immediately.
//   - otherwise → convert each side to an `Operand` and push a single pool node.
// ============================================================================

impl<EF: Field> Expr<EF> {
    /// Helper: apply a binary pool-op, folding Const-Const into a bare `Const`.
    fn binop<F: Fn(EF, EF) -> EF>(
        self,
        rhs: Self,
        scalar_op: F,
        make_node: fn(Operand<EF>, Operand<EF>) -> ExprNode<EF>,
    ) -> Self {
        match (self, rhs) {
            (Expr::Const(a), Expr::Const(b)) => Expr::Const(scalar_op(a, b)),
            (a, b) => {
                let pool = match (&a, &b) {
                    (Expr::Node(x), Expr::Node(y)) => {
                        debug_assert!(
                            Rc::ptr_eq(&x.pool, &y.pool),
                            "operands come from different expression pools",
                        );
                        x.pool.clone()
                    }
                    (Expr::Node(x), Expr::Const(_)) | (Expr::Const(_), Expr::Node(x)) => {
                        x.pool.clone()
                    }
                    (Expr::Const(_), Expr::Const(_)) => unreachable!(),
                };
                let to_operand = |e: Expr<EF>| match e {
                    Expr::Const(c) => Operand::Const(c),
                    Expr::Node(n) => Operand::Node(n.idx),
                };
                let idx = pool.borrow_mut().push(make_node(to_operand(a), to_operand(b)));
                Expr::Node(Element::new(pool, idx))
            }
        }
    }
}

impl<EF: Field> Add for Expr<EF> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.binop(rhs, |a, b| a + b, ExprNode::Add)
    }
}

impl<EF: Field> Sub for Expr<EF> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.binop(rhs, |a, b| a - b, ExprNode::Sub)
    }
}

impl<EF: Field> Mul for Expr<EF> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.binop(rhs, |a, b| a * b, ExprNode::Mul)
    }
}

impl<EF: Field> Neg for Expr<EF> {
    type Output = Self;
    fn neg(self) -> Self {
        match self {
            Expr::Const(a) => Expr::Const(-a),
            Expr::Node(_) => Expr::Const(EF::zero()) - self,
        }
    }
}

// Scalar ops: lift the bare `EF` to `Expr::Const` and delegate.

impl<EF: Field> Add<EF> for Expr<EF> {
    type Output = Self;
    fn add(self, rhs: EF) -> Self {
        self + Expr::Const(rhs)
    }
}

impl<EF: Field> Sub<EF> for Expr<EF> {
    type Output = Self;
    fn sub(self, rhs: EF) -> Self {
        self - Expr::Const(rhs)
    }
}

impl<EF: Field> Mul<EF> for Expr<EF> {
    type Output = Self;
    fn mul(self, rhs: EF) -> Self {
        self * Expr::Const(rhs)
    }
}

// Assign variants.

impl<EF: Field> AddAssign for Expr<EF> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<EF: Field> SubAssign for Expr<EF> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<EF: Field> MulAssign for Expr<EF> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

// Sum / Product for iterator usage.

impl<EF: Field> Sum for Expr<EF> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<EF: Field> Product for Expr<EF> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}

// ============================================================================
// AbstractField
// ============================================================================

impl<EF: Field> AbstractField for Expr<EF> {
    type F = EF;

    fn zero() -> Self {
        Expr::Const(EF::zero())
    }
    fn one() -> Self {
        Expr::Const(EF::one())
    }
    fn two() -> Self {
        Expr::Const(EF::two())
    }
    fn neg_one() -> Self {
        Expr::Const(EF::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        Expr::Const(f)
    }
    fn from_bool(b: bool) -> Self {
        Expr::Const(EF::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        Expr::Const(EF::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        Expr::Const(EF::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        Expr::Const(EF::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        Expr::Const(EF::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        Expr::Const(EF::from_canonical_usize(n))
    }
    fn from_wrapped_u32(n: u32) -> Self {
        Expr::Const(EF::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        Expr::Const(EF::from_wrapped_u64(n))
    }
    fn generator() -> Self {
        Expr::Const(EF::generator())
    }
}

// ============================================================================
// Evaluation.
// ============================================================================

/// Evaluate every node of the pool in one linear pass (no recursion; safe for
/// arbitrarily long linear combinations like those that come out of MLE openings).
///
/// Returns a `Vec<EF>` of the same length as the pool: `values[i]` is the concrete
/// extension-field value of node `i` when transcript slot `(g, l)` holds
/// `transcript[g][l]`.
pub fn evaluate_pool<EF: Field>(pool: &ExpressionPool<EF>, transcript: &[Vec<EF>]) -> Vec<EF> {
    let mut values = Vec::with_capacity(pool.len());
    let eval_operand = |op: Operand<EF>, values: &[EF]| match op {
        Operand::Node(i) => values[i],
        Operand::Const(c) => c,
    };
    for node in pool.nodes() {
        let v = match *node {
            ExprNode::Var(g, l) => transcript[g][l],
            ExprNode::Add(a, b) => eval_operand(a, &values) + eval_operand(b, &values),
            ExprNode::Sub(a, b) => eval_operand(a, &values) - eval_operand(b, &values),
            ExprNode::Mul(a, b) => eval_operand(a, &values) * eval_operand(b, &values),
        };
        values.push(v);
    }
    values
}

/// Evaluate a single [`Expr`] given the pool's pre-computed node values.
pub fn evaluate_expr<EF: Copy>(expr: &Expr<EF>, values: &[EF]) -> EF {
    match expr {
        Expr::Const(c) => *c,
        Expr::Node(e) => values[e.idx()],
    }
}
