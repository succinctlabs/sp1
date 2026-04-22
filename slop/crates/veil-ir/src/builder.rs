//! [`IrBuilder`] — the blessed `ConstraintCtx` + `ReadingCtx` implementation.
//!
//! Running any verifier function written as
//! `fn verify<C: ReadingCtx>(ctx: &mut C, ...)` against an `IrBuilder<F, E>`
//! produces a [`Program<E>`](crate::Program) that can be fed to any backend.

use std::cell::RefCell;
use std::hash::Hash;
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::rc::Rc;

use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_multilinear::Point;
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, TranscriptExhaustedError};

use crate::{Expr, ExprArena, ExprId, ExprKind, ExprType, OracleId, Program, Stmt, VarId};

type SharedArena<E> = Rc<RefCell<ExprArena<E>>>;

/// Arena-backed node that carries its arena reference, mirroring the pattern
/// used by `ExpressionIndex` in `slop_veil::zk::inner::constraints`.
pub struct ArenaNode<E> {
    id: ExprId,
    ty: ExprType,
    arena: SharedArena<E>,
}

impl<E> Clone for ArenaNode<E> {
    fn clone(&self) -> Self {
        Self { id: self.id, ty: self.ty, arena: Rc::clone(&self.arena) }
    }
}

/// The `Expr` / `Challenge` type the builder exposes.
///
/// Mirrors the Dorroh pattern: a handle is either a compile-time constant
/// (`Const`), which needs no arena, or a reference into the arena (`Node`).
/// `AbstractField` returns `Const` values, so constructing zeros and ones
/// requires no shared state.
pub struct ExprHandle<F: Field, E: ExtensionField<F>> {
    inner: HandleInner<E>,
    _marker: PhantomData<F>,
}

enum HandleInner<E> {
    Const(E),
    Node(ArenaNode<E>),
}

impl<E: Clone> Clone for HandleInner<E> {
    fn clone(&self) -> Self {
        match self {
            HandleInner::Const(e) => HandleInner::Const(e.clone()),
            HandleInner::Node(n) => HandleInner::Node(n.clone()),
        }
    }
}

impl<F: Field, E: ExtensionField<F>> Clone for ExprHandle<F, E> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), _marker: PhantomData }
    }
}

impl<F: Field, E: ExtensionField<F>> ExprHandle<F, E> {
    fn const_(value: E) -> Self {
        Self { inner: HandleInner::Const(value), _marker: PhantomData }
    }

    fn node(id: ExprId, ty: ExprType, arena: SharedArena<E>) -> Self {
        Self { inner: HandleInner::Node(ArenaNode { id, ty, arena }), _marker: PhantomData }
    }

    /// Materialize the handle into an arena-resident [`ExprId`], interning
    /// the constant variant if necessary.
    fn materialize(self, arena: &SharedArena<E>) -> (ExprId, ExprType)
    where
        E: Hash + Eq,
    {
        match self.inner {
            HandleInner::Node(n) => (n.id, n.ty),
            HandleInner::Const(v) => {
                let id = arena
                    .borrow_mut()
                    .intern(Expr { ty: ExprType::Ext, kind: ExprKind::ConstExt(v) });
                (id, ExprType::Ext)
            }
        }
    }
}

impl<F: Field, E: ExtensionField<F>> Default for ExprHandle<F, E> {
    fn default() -> Self {
        Self::const_(E::zero())
    }
}

impl<F: Field, E: ExtensionField<F>> std::fmt::Debug for ExprHandle<F, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            HandleInner::Const(_) => write!(f, "Const(..)"),
            HandleInner::Node(n) => write!(f, "Node({}, ty={:?})", n.id.0, n.ty),
        }
    }
}

// -----------------------------------------------------------------------------
// AbstractField: returns `Const` values; no arena needed.
// -----------------------------------------------------------------------------

impl<F: Field, E: ExtensionField<F>> AbstractField for ExprHandle<F, E> {
    type F = E;

    fn zero() -> Self {
        Self::const_(E::zero())
    }
    fn one() -> Self {
        Self::const_(E::one())
    }
    fn two() -> Self {
        Self::const_(E::two())
    }
    fn neg_one() -> Self {
        Self::const_(E::neg_one())
    }
    fn from_f(value: E) -> Self {
        Self::const_(value)
    }
    fn from_bool(b: bool) -> Self {
        Self::const_(E::from_bool(b))
    }
    fn from_canonical_u8(n: u8) -> Self {
        Self::const_(E::from_canonical_u8(n))
    }
    fn from_canonical_u16(n: u16) -> Self {
        Self::const_(E::from_canonical_u16(n))
    }
    fn from_canonical_u32(n: u32) -> Self {
        Self::const_(E::from_canonical_u32(n))
    }
    fn from_canonical_u64(n: u64) -> Self {
        Self::const_(E::from_canonical_u64(n))
    }
    fn from_canonical_usize(n: usize) -> Self {
        Self::const_(E::from_canonical_usize(n))
    }
    fn from_wrapped_u32(n: u32) -> Self {
        Self::const_(E::from_wrapped_u32(n))
    }
    fn from_wrapped_u64(n: u64) -> Self {
        Self::const_(E::from_wrapped_u64(n))
    }
    fn generator() -> Self {
        Self::const_(E::generator())
    }
}

// -----------------------------------------------------------------------------
// Note on `Into<Extension>`: `ConstraintCtx::Challenge` no longer requires
// `Into<Self::Extension>` — that bound was moved to `SendingCtx`, which
// `IrBuilder` does not implement. An arena-backed challenge has no concrete
// extension-field value at build time, so the bound would have been
// impossible to satisfy cleanly (the orphan rule blocks
// `impl From<ExprHandle<F, E>> for E` because `E` is a type parameter). See
// `slop/crates/veil/src/compiler/ctx.rs` for the relocated bound.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Arithmetic: ExprHandle + ExprHandle (covers `Algebra<Self>` via Module<Self>).
// -----------------------------------------------------------------------------

impl<F: Field, E: ExtensionField<F> + Hash + Eq> Add<Self> for ExprHandle<F, E> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        combine(self, rhs, |a, b| ExprKind::Add(a, b), |a, b| a + b)
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> Sub<Self> for ExprHandle<F, E> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        combine(self, rhs, |a, b| ExprKind::Sub(a, b), |a, b| a - b)
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> Mul<Self> for ExprHandle<F, E> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        combine(self, rhs, |a, b| ExprKind::Mul(a, b), |a, b| a * b)
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> Neg for ExprHandle<F, E> {
    type Output = Self;
    fn neg(self) -> Self {
        match self.inner {
            HandleInner::Const(v) => Self::const_(-v),
            HandleInner::Node(n) => {
                let id = n.arena.borrow_mut().intern(Expr { ty: n.ty, kind: ExprKind::Neg(n.id) });
                Self::node(id, n.ty, n.arena)
            }
        }
    }
}

fn combine<F: Field, E: ExtensionField<F> + Hash + Eq>(
    lhs: ExprHandle<F, E>,
    rhs: ExprHandle<F, E>,
    mk: fn(ExprId, ExprId) -> ExprKind<E>,
    const_op: fn(E, E) -> E,
) -> ExprHandle<F, E> {
    match (lhs.inner, rhs.inner) {
        (HandleInner::Const(a), HandleInner::Const(b)) => ExprHandle::const_(const_op(a, b)),
        (lhs_inner, rhs_inner) => {
            let arena = match (&lhs_inner, &rhs_inner) {
                (HandleInner::Node(n), _) => Rc::clone(&n.arena),
                (_, HandleInner::Node(n)) => Rc::clone(&n.arena),
                _ => unreachable!(),
            };
            let lhs_h = ExprHandle { inner: lhs_inner, _marker: PhantomData };
            let rhs_h = ExprHandle { inner: rhs_inner, _marker: PhantomData };
            let (a_id, _) = lhs_h.materialize(&arena);
            let (b_id, _) = rhs_h.materialize(&arena);
            let id = arena.borrow_mut().intern(Expr { ty: ExprType::Ext, kind: mk(a_id, b_id) });
            ExprHandle::node(id, ExprType::Ext, arena)
        }
    }
}

// -----------------------------------------------------------------------------
// Module<E>: arithmetic with concrete extension-field values (covers
// `Algebra<Extension>`).
// -----------------------------------------------------------------------------

impl<F: Field, E: ExtensionField<F> + Hash + Eq> Add<E> for ExprHandle<F, E> {
    type Output = Self;
    fn add(self, rhs: E) -> Self {
        self + Self::const_(rhs)
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> Sub<E> for ExprHandle<F, E> {
    type Output = Self;
    fn sub(self, rhs: E) -> Self {
        self - Self::const_(rhs)
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> Mul<E> for ExprHandle<F, E> {
    type Output = Self;
    fn mul(self, rhs: E) -> Self {
        self * Self::const_(rhs)
    }
}

// -----------------------------------------------------------------------------
// *Assign variants — required by AbstractField.
// -----------------------------------------------------------------------------

impl<F: Field, E: ExtensionField<F> + Hash + Eq> AddAssign<Self> for ExprHandle<F, E> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> SubAssign<Self> for ExprHandle<F, E> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> MulAssign<Self> for ExprHandle<F, E> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

// -----------------------------------------------------------------------------
// Sum / Product — required by AbstractField.
// -----------------------------------------------------------------------------

impl<F: Field, E: ExtensionField<F> + Hash + Eq> Sum for ExprHandle<F, E> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + b)
    }
}
impl<F: Field, E: ExtensionField<F> + Hash + Eq> Product for ExprHandle<F, E> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |a, b| a * b)
    }
}

// -----------------------------------------------------------------------------
// IrBuilder
// -----------------------------------------------------------------------------

/// Build a [`Program`] by running a verifier function against this context.
pub struct IrBuilder<F: Field, E: ExtensionField<F>> {
    arena: SharedArena<E>,
    stmts: Vec<Stmt>,
    next_var: u32,
    next_oracle: u32,
    _marker: PhantomData<F>,
}

impl<F: Field, E: ExtensionField<F> + Hash + Eq> Default for IrBuilder<F, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, E: ExtensionField<F> + Hash + Eq> IrBuilder<F, E> {
    pub fn new() -> Self {
        Self {
            arena: Rc::new(RefCell::new(ExprArena::new())),
            stmts: Vec::new(),
            next_var: 0,
            next_oracle: 0,
            _marker: PhantomData,
        }
    }

    /// Consume the builder and return the produced [`Program`].
    ///
    /// # Panics
    /// If any [`ExprHandle`] produced by this builder is still live. Handles
    /// share ownership of the arena via `Rc`; all must be dropped first.
    pub fn finish(self) -> Program<E> {
        let arena = Rc::try_unwrap(self.arena)
            .unwrap_or_else(|_| panic!("IrBuilder::finish called while ExprHandles are still live"))
            .into_inner();
        Program {
            stmts: self.stmts,
            exprs: arena,
            num_vars: self.next_var,
            num_oracles: self.next_oracle,
        }
    }

    fn alloc_vars(&mut self, count: u32) -> VarId {
        let start = VarId(self.next_var);
        self.next_var += count;
        start
    }

    fn alloc_oracle(&mut self) -> OracleId {
        let id = OracleId(self.next_oracle);
        self.next_oracle += 1;
        id
    }

    fn make_var_handle(&self, var: VarId, ty: ExprType) -> ExprHandle<F, E> {
        let kind = match ty {
            ExprType::Ext => ExprKind::Var(var),
            ExprType::Challenge => ExprKind::Challenge(var),
        };
        let id = self.arena.borrow_mut().intern(Expr { ty, kind });
        ExprHandle::node(id, ty, Rc::clone(&self.arena))
    }
}

impl<F, E> ConstraintCtx for IrBuilder<F, E>
where
    F: Field,
    E: ExtensionField<F> + Hash + Eq,
{
    type Field = F;
    type Extension = E;
    type Expr = ExprHandle<F, E>;
    type Challenge = ExprHandle<F, E>;
    type MleOracle = OracleId;

    fn assert_zero(&mut self, expr: Self::Expr) {
        let (id, _) = expr.materialize(&self.arena);
        self.stmts.push(Stmt::AssertZero(id));
    }

    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr) {
        let (a_id, _) = a.materialize(&self.arena);
        let (b_id, _) = b.materialize(&self.arena);
        let (c_id, _) = c.materialize(&self.arena);
        self.stmts.push(Stmt::AssertProduct(a_id, b_id, c_id));
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleOracle, Self::Expr)>,
        point: Point<Self::Challenge>,
    ) {
        let arena = Rc::clone(&self.arena);
        let lowered_claims: Vec<(OracleId, ExprId)> = claims
            .into_iter()
            .map(|(oracle, eval)| {
                let (id, _) = eval.materialize(&arena);
                (oracle, id)
            })
            .collect();
        let point_vec: Vec<ExprId> = point
            .iter()
            .cloned()
            .map(|c| {
                let (id, _) = c.materialize(&arena);
                id
            })
            .collect();
        self.stmts.push(Stmt::AssertMleMultiEval { claims: lowered_claims, point: point_vec });
    }
}

impl<F, E> ReadingCtx for IrBuilder<F, E>
where
    F: Field,
    E: ExtensionField<F> + Hash + Eq,
{
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptExhaustedError> {
        let count = buf.len() as u32;
        if count == 0 {
            return Ok(());
        }
        let start = self.alloc_vars(count);
        self.stmts.push(Stmt::ReadTranscript { start, count });
        for (i, slot) in buf.iter_mut().enumerate() {
            let var = VarId(start.0 + i as u32);
            *slot = self.make_var_handle(var, ExprType::Ext);
        }
        Ok(())
    }

    fn read_oracle(
        &mut self,
        num_encoding_variables: u32,
        log_num_polynomials: u32,
    ) -> Option<OracleId> {
        let dst = self.alloc_oracle();
        self.stmts.push(Stmt::ReadOracle { dst, num_encoding_variables, log_num_polynomials });
        Some(dst)
    }

    fn sample(&mut self) -> Self::Challenge {
        let dst = self.alloc_vars(1);
        self.stmts.push(Stmt::Sample { dst });
        self.make_var_handle(dst, ExprType::Challenge)
    }
}
