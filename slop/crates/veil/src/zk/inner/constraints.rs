use std::{
    collections::HashMap,
    ops::{Add, Mul, Neg, Sub},
};

use derive_where::derive_where;
use itertools::Itertools;
use slop_algebra::AbstractField;

use super::transcript::{
    MleCommitmentIndex, Point, TranscriptIndex, TranscriptLinConstraint, TranscriptMulConstraint,
};
use super::ZkIopCtx;

/// This trait provides the shared functionality needed by both prover and verifier
/// contexts for adding and manipulating constraints
pub trait ConstraintContextInner<K: AbstractField + Copy>: Clone {
    /// The element type for this context (ProverElement or VerifierElement)
    type Element: ZkElement<K>;

    /// Adds multiple linear constraints to the context.
    fn add_lin_constraints(
        &mut self,
        constraints: impl IntoIterator<Item = TranscriptLinConstraint<K>>,
    );

    /// Adds multiple multiplicative constraints to the context.
    fn add_mul_constraints(
        &mut self,
        constraints: impl IntoIterator<Item = TranscriptMulConstraint<K>>,
    );

    /// Adds a linear constraint to the context.
    fn add_lin_constraint(&mut self, constraint: TranscriptLinConstraint<K>) {
        self.add_lin_constraints(std::iter::once(constraint));
    }

    /// Adds a multiplicative constraint to the context.
    fn add_mul_constraint(&mut self, constraint: TranscriptMulConstraint<K>) {
        self.add_mul_constraints(std::iter::once(constraint));
    }

    /// Shorthand for adding the multiplicative constraint ab=c from expressions a,b,c.
    fn constrain_mul_triple<A, B, C>(&mut self, a: A, b: B, c: C)
    where
        A: Into<TranscriptLinConstraint<K>>,
        B: Into<TranscriptLinConstraint<K>>,
        C: Into<TranscriptLinConstraint<K>>,
    {
        self.add_mul_constraint(TranscriptMulConstraint::from_lin_constraints(
            a.into(),
            b.into(),
            c.into(),
        ));
    }

    /// Names the most recently added linear constraint (for debugging).
    ///
    /// Only available when compiled with `sp1_debug_constraints`.
    /// Use the `name_constraint!` macro instead of calling this directly.
    #[cfg(sp1_debug_constraints)]
    fn name_last_lin_constraint_inner(&self, _name: impl Into<String>) {}

    /// Add to the flattened AST of expressions, returning an [`ExpressionIndex`].
    fn add_expr(&mut self, expr: ZkExpression<K, Self::Element>) -> ExpressionIndex<K, Self>;

    /// Read from the flattened AST of expressions, returning the expression if it exists.
    fn get_expr(&self, index: usize) -> Option<ZkExpression<K, Self::Element>>;

    /// Materialize a product of two elements.
    ///
    /// Adds a new transcript element for the product and adds the corresponding
    /// multiplicative constraint to the context.
    ///
    /// Outputs the expression for the new element.
    fn materialize_prod(
        &mut self,
        a: <Self::Element as ZkElement<K>>::LinExpr,
        b: <Self::Element as ZkElement<K>>::LinExpr,
    ) -> Option<Self::Element>;

    /// Adds a (possibly batched) PCS evaluation claim for one or more commitments at the same point.
    ///
    /// A single commitment produces a length-1 claim; multiple commitments at the same point
    /// produce a batched proof.
    fn add_eval_claim(
        &mut self,
        commitment_indices: Vec<MleCommitmentIndex>,
        point: Point<K>,
        eval_exprs: Vec<ExpressionIndex<K, Self>>,
    );

    fn assert_zero_inner(&mut self, expr: ExpressionIndex<K, Self>) {
        let constraint = expr.into_expr();
        self.add_lin_constraint(constraint.into());
    }

    fn assert_a_times_b_equals_c_inner(
        &mut self,
        a: ExpressionIndex<K, Self>,
        b: ExpressionIndex<K, Self>,
        c: ExpressionIndex<K, Self>,
    ) {
        let a_expr = a.into_expr();
        let b_expr = b.into_expr();
        let c_expr = c.into_expr();
        self.constrain_mul_triple(a_expr, b_expr, c_expr);
    }

    /// Add a constant as an expression in the context.
    fn cst_inner(&mut self, value: K) -> ExpressionIndex<K, Self> {
        self.add_expr(ZkExpression::Cst(value))
    }

    /// Folds an expression tree into a single value using the provided closures.
    ///
    /// # Arguments
    /// * `index` - The root expression index to fold
    /// * `cst_fn` - Handles `Cst` variants, producing an `R` from `K`
    /// * `elem_fn` - Handles `Element` variants, producing an `R` from `Self::Element`
    /// * `add_fn` - Combines two `R` values for `Add` nodes
    /// * `sub_fn` - Combines two `R` values for `Sub` nodes
    /// * `scale_fn` - Scales an `R` value by a field element `K`
    /// * `zero_fn` - Produces the zero value of type `R`
    #[allow(clippy::too_many_arguments)]
    fn fold_expression<R>(
        &self,
        index: usize,
        cst_fn: impl Fn(K) -> R,
        elem_fn: impl Fn(Self::Element) -> R,
        add_fn: impl Fn(R, R) -> R,
        sub_fn: impl Fn(R, R) -> R,
        scale_fn: impl Fn(R, K) -> R,
        zero_fn: impl Fn() -> R,
    ) -> R {
        let mut node_stack: Vec<usize> = vec![index];
        let mut results = HashMap::<usize, R>::new();

        while let Some(&cur_index) = node_stack.last() {
            let cur_expr = self.get_expr(cur_index).expect("bad expression index");
            match cur_expr {
                ZkExpression::Cst(c) => {
                    node_stack.pop();
                    results.insert(cur_index, cst_fn(c));
                }
                ZkExpression::Element(elem) => {
                    node_stack.pop();
                    results.insert(cur_index, elem_fn(elem));
                }
                ZkExpression::Add(lhs, rhs) | ZkExpression::Sub(lhs, rhs) => {
                    if lhs == rhs {
                        if let Some(lhs_val) = results.remove(&lhs) {
                            node_stack.pop();
                            let result = match cur_expr {
                                // x + x = 2x
                                ZkExpression::Add(..) => {
                                    scale_fn(lhs_val, K::from_canonical_u16(2))
                                }
                                // x - x = 0
                                _ => zero_fn(),
                            };
                            results.insert(cur_index, result);
                        } else {
                            node_stack.push(lhs);
                        }
                    } else {
                        let have_lhs = results.contains_key(&lhs);
                        let have_rhs = results.contains_key(&rhs);
                        if have_lhs && have_rhs {
                            let lhs_val = results.remove(&lhs).unwrap();
                            let rhs_val = results.remove(&rhs).unwrap();
                            node_stack.pop();
                            let result = match cur_expr {
                                ZkExpression::Add(..) => add_fn(lhs_val, rhs_val),
                                _ => sub_fn(lhs_val, rhs_val),
                            };
                            results.insert(cur_index, result);
                        } else if have_lhs {
                            node_stack.push(rhs);
                        } else {
                            node_stack.push(lhs);
                        }
                    }
                }
                ZkExpression::Scale(idx, scalar) => {
                    if let Some(inner_val) = results.remove(&idx) {
                        node_stack.pop();
                        results.insert(cur_index, scale_fn(inner_val, scalar));
                    } else {
                        node_stack.push(idx);
                    }
                }
            }
        }

        results.remove(&index).expect("should have computed result")
    }

    /// Converts an expression index to a linear expression.
    fn index_to_lin_expression(&self, index: usize) -> <Self::Element as ZkElement<K>>::LinExpr {
        self.fold_expression(
            index,
            |c| c.into(),
            |elem| elem.into(),
            |lhs, rhs| lhs + rhs,
            |lhs, rhs| lhs - rhs,
            |val, scalar| val * scalar,
            || K::zero().into(),
        )
    }
}

/// Trait for elements in a ZK transcript (prover or verifier side).
///
/// An element represents a value in the transcript, identified by its index.
/// Prover elements also carry the actual value; verifier elements only have the index.
///
/// Elements support:
/// - Scalar Multiplication (`Mul<K>`) which returns an expression
/// - Addition and subtraction (`Add<Self>`, `Sub<Self>`) which return expressions
pub trait ZkElement<K: AbstractField>:
    Copy
    + std::fmt::Debug
    + Into<TranscriptIndex<K>>
    + Into<TranscriptLinConstraint<K>>
    + Add<Self, Output = Self::LinExpr>
    + Sub<Self, Output = Self::LinExpr>
    + Mul<K, Output = Self::LinExpr>
{
    /// The expression type that results from arithmetic on this element.
    type LinExpr: ZkLinExpression<K, Self>;
}

/// Trait for linear expressions in a ZK transcript (prover or verifier side).
pub trait ZkLinExpression<K: AbstractField, E: ZkElement<K, LinExpr = Self>>:
    Clone
    + std::fmt::Debug
    + From<E>
    + From<K>
    + Into<TranscriptLinConstraint<K>>
    + Add<Self, Output = Self>
    + Add<E, Output = Self>
    + Sub<Self, Output = Self>
    + Sub<E, Output = Self>
    + Mul<K, Output = Self>
{
}

/// An expression in the flattened AST of expressions.
///
/// Note that there is no need for a `Mul` variant here since the output of multiplication
/// is automatically materialized into the proof transcript.
#[derive(Clone, Copy, Debug)]
pub enum ZkExpression<K, E> {
    Cst(K),
    Element(E),
    Add(usize, usize),
    Sub(usize, usize),
    Scale(usize, K),
}

impl<K: AbstractField, E: ZkElement<K>> From<E> for ZkExpression<K, E> {
    fn from(elem: E) -> Self {
        ZkExpression::Element(elem)
    }
}

// ============================================================================
// ExpressionIndex
// ============================================================================

/// The index handle for expressions in the flattened AST of expressions.
#[derive_where(Clone; C: Clone)]
pub struct ExpressionIndex<K, C> {
    index: usize,
    context: C,
    _phantom_data: std::marker::PhantomData<K>,
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> ExpressionIndex<K, C> {
    pub(in crate::zk::inner) fn new(index: usize, context: C) -> Self {
        Self { index, context, _phantom_data: std::marker::PhantomData }
    }

    pub fn into_expr(self) -> <C::Element as ZkElement<K>>::LinExpr {
        self.as_ref().clone().index_to_lin_expression(self.index)
    }

    pub fn index(&self) -> usize {
        self.index
    }

    /// Attempts to convert this expression index into a `TranscriptIndex` if it corresponds to an element.
    /// Returns `None` if the expression is not a single element.
    ///
    /// Mainly for use directly with outputs of ZkVerifierContext reads or ZkProverContext adds
    pub fn try_into_index(self) -> Option<TranscriptIndex<K>> {
        let expr = self.as_ref().clone().get_expr(self.index)?;
        match expr {
            ZkExpression::Element(elem) => Some(elem.into()),
            _ => None,
        }
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> std::fmt::Debug
    for ExpressionIndex<K, C>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.index)
    }
}

impl<K, C: Clone> AsRef<C> for ExpressionIndex<K, C> {
    fn as_ref(&self) -> &C {
        &self.context
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> From<ExpressionIndex<K, C>>
    for TranscriptLinConstraint<K>
{
    fn from(expr: ExpressionIndex<K, C>) -> Self {
        expr.into_expr().into()
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Add<ExpressionIndex<K, C>>
    for ExpressionIndex<K, C>
{
    type Output = Self;

    fn add(self, rhs: ExpressionIndex<K, C>) -> Self::Output {
        let expr = ZkExpression::Add(self.index, rhs.index);
        self.as_ref().clone().add_expr(expr)
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Add<K> for ExpressionIndex<K, C> {
    type Output = Self;

    fn add(self, rhs: K) -> Self::Output {
        let index_rhs = self.as_ref().clone().add_expr(ZkExpression::Cst(rhs));
        self + index_rhs
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Sub<K> for ExpressionIndex<K, C> {
    type Output = Self;

    fn sub(self, rhs: K) -> Self::Output {
        let index_rhs = self.as_ref().clone().add_expr(ZkExpression::Cst(rhs));
        self - index_rhs
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Neg for ExpressionIndex<K, C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let index_zero = self.as_ref().clone().add_expr(ZkExpression::Cst(K::zero()));
        index_zero - self
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Sub<ExpressionIndex<K, C>>
    for ExpressionIndex<K, C>
{
    type Output = Self;

    fn sub(self, rhs: ExpressionIndex<K, C>) -> Self::Output {
        let expr = ZkExpression::Sub(self.index, rhs.index);
        self.as_ref().clone().add_expr(expr)
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Mul<K> for ExpressionIndex<K, C> {
    type Output = Self;

    fn mul(self, rhs: K) -> Self::Output {
        let expr = ZkExpression::Scale(self.index, rhs);
        self.as_ref().clone().add_expr(expr)
    }
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K>> Mul<ExpressionIndex<K, C>>
    for ExpressionIndex<K, C>
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ctx = self.as_ref().clone();

        let lhs_expr = self.into_expr();
        let rhs_expr = rhs.into_expr();

        let new_elem = ctx
            .materialize_prod(lhs_expr, rhs_expr)
            .expect("Failed to materialize product of two expressions");
        ctx.add_expr(ZkExpression::Element(new_elem))
    }
}

// ============================================================================
// Public interface setup
// ============================================================================

/// Public interface for [`ConstraintContextInner`]
pub trait ConstraintContextInnerExt<K: AbstractField + Copy>: Clone {
    type Expr: Clone
        + std::fmt::Debug
        + AsRef<Self>
        + Add<K, Output = Self::Expr>
        + Add<Self::Expr, Output = Self::Expr>
        + Sub<K, Output = Self::Expr>
        + Sub<Self::Expr, Output = Self::Expr>
        + Mul<K, Output = Self::Expr>
        + Mul<Self::Expr, Output = Self::Expr>;

    fn assert_zero(&mut self, expr: Self::Expr);

    /// assert_zero(a * b - c) materializes the product of a and b. This is unnecessary specifically
    /// for constraints of the form a * b = c. Use this instead to avoid the extra materialization.
    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr);

    /// Add a constant as an expression in the context.
    fn cst(&mut self, value: K) -> Self::Expr;

    #[cfg(sp1_debug_constraints)]
    fn name_last_lin_constraint(&self, _name: impl Into<String>) {}

    /// Creates an expression from a polynomial evaluation: `poly(point)`.
    ///
    /// Computes: `coeff_0 + point * coeff_1 + ... + point^{n-1} * coeff_n`
    fn poly_eval(poly: &[Self::Expr], point: K) -> Self::Expr {
        let mut iter = poly.iter().rev();
        let first = iter.next().expect("poly_eval requires non-empty polynomial").clone();
        iter.fold(first, |acc, term| acc * point + term.clone())
    }

    /// Creates an expression from `eval(1) + eval(0)` of a polynomial.
    ///
    /// Computes: `2 * coeff_0 + coeff_1 + ... + coeff_n`
    fn eval_one_plus_eval_zero(poly: &[Self::Expr]) -> Self::Expr {
        let mut iter = poly.iter();
        let first = iter.next().expect("eval_one_plus_eval_zero requires non-empty polynomial");
        // Start with 2 * coeff_0, then add the rest
        let two_first = first.clone() + first.clone();
        iter.fold(two_first, |acc, term| acc + term.clone())
    }

    /// Creates an expression from an MLE evaluation at point.
    ///
    /// Assumes the input vec of elements' entries are the evaluations of the MLE
    /// on the hypercube in standard order.
    ///
    /// # Panics
    ///
    /// Requires exactly 2^{dim(Point)} many entries in `coeffs`.
    fn mle_eval(point: slop_multilinear::Point<K>, coeffs: &[Self::Expr]) -> Self::Expr {
        use slop_multilinear::partial_lagrange_blocking;

        let lagrange_coeffs = partial_lagrange_blocking(&point).into_buffer().into_vec();

        let mut iter = lagrange_coeffs.into_iter().zip_eq(coeffs.iter());
        let (first_coeff, first_index) =
            iter.next().expect("mle_eval requires non-empty coefficients");
        let first = first_index.clone() * first_coeff;
        iter.fold(first, |acc, (coeff, index)| acc + index.clone() * coeff)
    }

    /// Asserts that a committed MLE evaluates to `eval_expr` at `point`.
    ///
    /// Registers an evaluation claim that will be proven/verified during
    /// the PCS proof generation/verification phase.
    ///
    /// Default implementation delegates to `assert_mle_multi_eval` with a single claim.
    fn assert_mle_eval(
        &mut self,
        commitment_index: MleCommitmentIndex,
        point: Point<K>,
        eval_expr: Self::Expr,
    ) {
        self.assert_mle_multi_eval(vec![(commitment_index, eval_expr)], point);
    }

    /// Asserts that multiple committed MLEs evaluate to the given values at a shared point.
    ///
    /// This produces a single batched PCS proof covering all commitments,
    /// which is more efficient than calling `assert_mle_eval` once per commitment.
    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(MleCommitmentIndex, Self::Expr)>,
        point: Point<K>,
    );
}

pub(in crate::zk::inner) mod private {
    /// Stupid hoop to jump through since Rust doesn't allow negative trait bounds, thereby making
    /// blanket implementations difficult
    pub trait Sealed {}
}

impl<K: AbstractField + Copy, C: ConstraintContextInner<K> + private::Sealed>
    ConstraintContextInnerExt<K> for C
{
    type Expr = ExpressionIndex<K, C>;

    #[cfg_attr(sp1_debug_constraints, track_caller)]
    fn assert_zero(&mut self, expr: Self::Expr) {
        self.assert_zero_inner(expr);
        #[cfg(sp1_debug_constraints)]
        {
            let loc = std::panic::Location::caller();
            self.name_last_lin_constraint_inner(format!("{}:{}", loc.file(), loc.line()));
        }
    }

    #[cfg_attr(sp1_debug_constraints, track_caller)]
    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr) {
        self.assert_a_times_b_equals_c_inner(a, b, c)
    }

    fn cst(&mut self, value: K) -> Self::Expr {
        self.cst_inner(value)
    }

    #[cfg(sp1_debug_constraints)]
    fn name_last_lin_constraint(&self, name: impl Into<String>) {
        self.name_last_lin_constraint_inner(name)
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(MleCommitmentIndex, Self::Expr)>,
        point: Point<K>,
    ) {
        let (commitment_indices, eval_exprs): (Vec<_>, Vec<_>) = claims.into_iter().unzip();
        self.add_eval_claim(commitment_indices, point, eval_exprs)
    }
}

/// Trait for reading ProofTranscripts
pub trait ZkCnstrAndReadingCtxInner<GC: ZkIopCtx>: ConstraintContextInnerExt<GC::EF> {
    /// Read the next single element from the transcript.
    fn read_one(&mut self) -> Option<Self::Expr> {
        self.read_next(1)?.pop()
    }

    /// Read the next `num` elements from the transcript
    fn read_next(&mut self, num: usize) -> Option<Vec<Self::Expr>>;

    /// Returns a mutable reference to the challenger for Fiat-Shamir.
    fn challenger(&mut self) -> std::cell::RefMut<'_, GC::Challenger>;

    /// Reads the next PCS commitment from the transcript.
    ///
    /// Checks that the parameters match and observes the commitment in the Fiat-Shamir challenger.
    ///
    /// # Arguments
    /// * `num_vars` — number of variables per stacked polynomial (encoding width).
    ///   Must match the value the PCS was initialized with.
    /// * `log_num_polys` — log2 of the number of stacked polynomials (tensor height).
    ///
    /// # Returns
    /// `Some(MleCommitmentIndex)` if successful, `None` if parameters don't match
    /// or there are no more commitments.
    fn read_next_pcs_commitment(
        &mut self,
        num_vars: usize,
        log_num_polys: usize,
    ) -> Option<MleCommitmentIndex>;
}
