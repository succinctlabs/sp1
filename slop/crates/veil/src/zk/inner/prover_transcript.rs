use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use slop_algebra::AbstractField;

use super::{
    ConstraintContextInner, ExpressionIndex, TranscriptIndex, TranscriptLinConstraint, ZkElement,
    ZkIopCtx, ZkLinExpression, ZkMerkleizer, ZkProverContext,
};

// ============================================================================
// Type Definitions
// ============================================================================

/// An element in the proof transcript, identified by its (unmasked!) value and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProverElement<K: AbstractField> {
    value: K,
    index: TranscriptIndex<K>,
}

impl<K: AbstractField + Copy> ProverElement<K> {
    /// Creates a new `ProverElement` with the given value and index.
    pub fn new(value: K, index: TranscriptIndex<K>) -> Self {
        Self { value, index }
    }

    /// Returns the unmasked value of this element.
    pub fn value(&self) -> K {
        self.value
    }
}

/// A linear expression in the proof transcript, identified by its value and linear constraint.
#[derive(Debug, Clone)]
pub struct ProverLinExpression<K: AbstractField> {
    value: K,
    expr: TranscriptLinConstraint<K>,
}

impl<K: AbstractField + Copy> ProverLinExpression<K> {
    /// Creates a new `ProverLinExpression` with the given value and expression.
    pub fn new(value: K, expr: TranscriptLinConstraint<K>) -> Self {
        Self { value, expr }
    }

    /// Returns the value of this linear expression.
    pub fn value(&self) -> K {
        self.value
    }
}

// ============================================================================
// ProverElement impls
// ============================================================================

impl<K: AbstractField + Copy> From<ProverElement<K>> for TranscriptIndex<K> {
    fn from(element: ProverElement<K>) -> Self {
        element.index
    }
}

impl<K: AbstractField + Copy> From<ProverElement<K>> for TranscriptLinConstraint<K> {
    fn from(element: ProverElement<K>) -> Self {
        element.index.into()
    }
}

impl<K: AbstractField + Copy> From<ProverElement<K>> for ProverLinExpression<K> {
    fn from(element: ProverElement<K>) -> Self {
        ProverLinExpression::new(element.value, element.into())
    }
}

impl<K, T> Add<T> for ProverElement<K>
where
    K: AbstractField + Copy,
    T: Into<ProverLinExpression<K>>,
{
    type Output = ProverLinExpression<K>;

    fn add(self, rhs: T) -> Self::Output {
        ProverLinExpression::from(self) + rhs
    }
}

impl<K, T> Sub<T> for ProverElement<K>
where
    K: AbstractField + Copy,
    T: Into<ProverLinExpression<K>>,
{
    type Output = ProverLinExpression<K>;

    fn sub(self, rhs: T) -> Self::Output {
        ProverLinExpression::from(self) - rhs
    }
}

impl<K: AbstractField + Copy> Mul<K> for ProverElement<K> {
    type Output = ProverLinExpression<K>;

    fn mul(self, scalar: K) -> Self::Output {
        ProverLinExpression::from(self) * scalar
    }
}

// ============================================================================
// ProverExpression impls
// ============================================================================

impl<K: AbstractField + Copy> From<K> for ProverLinExpression<K> {
    fn from(value: K) -> Self {
        ProverLinExpression::new(value, value.into())
    }
}

impl<K: AbstractField + Copy> From<ProverLinExpression<K>> for TranscriptLinConstraint<K> {
    fn from(expr: ProverLinExpression<K>) -> Self {
        expr.expr
    }
}

impl<K, T> Add<T> for ProverLinExpression<K>
where
    K: AbstractField + Copy,
    T: Into<ProverLinExpression<K>>,
{
    type Output = Self;

    fn add(mut self, rhs: T) -> Self::Output {
        self += rhs.into();
        self
    }
}

impl<K, T> Sub<T> for ProverLinExpression<K>
where
    K: AbstractField + Copy,
    T: Into<ProverLinExpression<K>>,
{
    type Output = Self;

    fn sub(mut self, rhs: T) -> Self::Output {
        self -= rhs.into();
        self
    }
}

impl<K: AbstractField + Copy> Mul<K> for ProverLinExpression<K> {
    type Output = Self;

    fn mul(mut self, scalar: K) -> Self::Output {
        self *= scalar;
        self
    }
}

impl<K, T> AddAssign<T> for ProverLinExpression<K>
where
    K: AbstractField + Copy,
    T: Into<ProverLinExpression<K>>,
{
    fn add_assign(&mut self, rhs: T) {
        let rhs = rhs.into();
        self.expr += rhs.expr;
        self.value += rhs.value;
    }
}

impl<K, T> SubAssign<T> for ProverLinExpression<K>
where
    K: AbstractField + Copy,
    T: Into<ProverLinExpression<K>>,
{
    fn sub_assign(&mut self, rhs: T) {
        let rhs = rhs.into();
        self.expr -= rhs.expr;
        self.value -= rhs.value;
    }
}

impl<K: AbstractField + Copy> MulAssign<K> for ProverLinExpression<K> {
    fn mul_assign(&mut self, scalar: K) {
        self.expr *= scalar;
        self.value *= scalar;
    }
}

// ============================================================================
// Trait implementations
// ============================================================================

impl<K: AbstractField + Copy> ZkElement<K> for ProverElement<K> {
    type LinExpr = ProverLinExpression<K>;
}

impl<K: AbstractField + Copy> ZkLinExpression<K, ProverElement<K>> for ProverLinExpression<K> {}

#[allow(type_alias_bounds)]
/// Placeholder Value!
pub type ProverValue<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD = ()> =
    ExpressionIndex<GC::EF, ZkProverContext<GC, MK, PD>>;

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD: Clone>
    ExpressionIndex<GC::EF, ZkProverContext<GC, MK, PD>>
{
    /// Computes just the value associated to a given Prover Expression Index.
    ///
    /// This is an optimization that doesn't also compute the linear expression.
    pub fn value(&self) -> GC::EF {
        self.as_ref().clone().fold_expression(
            self.index(),
            |c| c,
            |elem| elem.value(),
            |lhs, rhs| lhs + rhs,
            |lhs, rhs| lhs - rhs,
            |val, scalar| val * scalar,
            GC::EF::zero,
        )
    }
}
