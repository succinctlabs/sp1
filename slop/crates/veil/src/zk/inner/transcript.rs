use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use slop_multilinear::partial_lagrange_blocking;
pub use slop_multilinear::Point;

/// Wraps masked values and their breakpoints for the proof.
///
/// A jagged array stored as a flat array with breakpoints indicating the start of each block.
/// In actual use, the first block will always be length 1 with a value of 1 to allow for
/// affine constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "K: Serialize", deserialize = "K: serde::de::DeserializeOwned"))]
pub struct ProofTranscript<K>
where
    K: AbstractField,
{
    pub values: Vec<K>,
    pub values_break_points: Vec<usize>,
}

impl<K> ProofTranscript<K>
where
    K: AbstractField + Copy,
{
    /// Creates a new `ProofTranscript` with zero-initialized values and a single breakpoint at 0.
    pub fn new(length: usize) -> Self {
        Self { values: vec![K::zero(); length], values_break_points: vec![0] }
    }

    /// Turns a jagged array index into a flat array index.
    pub fn to_flat_index<T: slop_algebra::AbstractField>(
        &self,
        index: &TranscriptIndex<T>,
    ) -> usize {
        self.values_break_points[index.inner[0]] + index.inner[1]
    }

    /// Adds masked values to the array.
    ///
    /// Returns the length of the values after addition.
    ///
    /// # Panics
    ///
    /// Panics if we exceed the allocated length.
    pub fn add_values(&mut self, values: &[K]) -> usize {
        let current_index = self.values_break_points.last().unwrap();
        for (i, &value) in values.iter().enumerate() {
            self.values[current_index + i] = value;
        }
        let new_index = current_index + values.len();
        self.values_break_points.push(new_index);
        new_index
    }

    /// Gets the values at block index `i`.
    pub fn get_values(&self, i: usize) -> Option<&[K]> {
        let start = *self.values_break_points.get(i)?;
        let end = *self.values_break_points.get(i + 1)?;
        self.values.get(start..end)
    }

    /// Returns the index of the next block to be added.
    ///
    /// The indexing is: `self.values_break_points[self.next_block_index()]` is the start
    /// index of the next block.
    pub fn next_block_index(&self) -> usize {
        self.values_break_points.len() - 1
    }

    /// Gets the current number of values stored.
    pub fn current_length(&self) -> usize {
        *self.values_break_points.last().expect("values_break_points should never be empty")
    }

    /// Generates the dot product vector from RLC'ing a set of linear constraints.
    pub fn generate_rlc_dot_vector(
        &self,
        constraints: &[TranscriptLinConstraint<K>],
        rlc_coeff: K,
    ) -> Vec<K> {
        let mut dot_vec: Vec<K> = vec![K::zero(); self.values.len()];
        let mut scale = K::one();
        constraints.iter().for_each(|constraint| {
            constraint.0.iter().for_each(|(coeff, index)| {
                let flat_index = self.to_flat_index(index);
                dot_vec[flat_index] += *coeff * scale;
            });
            scale *= rlc_coeff;
        });
        dot_vec
    }

    /// Converts a single constraint to a dot product vector for debugging.
    pub fn single_constraint_to_dot_vector(
        &self,
        constraint: &TranscriptLinConstraint<K>,
    ) -> Vec<K> {
        let mut dot_vec: Vec<K> = vec![K::zero(); self.values.len()];
        constraint.0.iter().for_each(|(coeff, index)| {
            let flat_index = self.to_flat_index(index);
            dot_vec[flat_index] += *coeff;
        });
        dot_vec
    }

    /// Generates the linear constraints needed to see if multiplicative constraints
    /// were picked out correctly from the vector of ProofValues
    ///
    /// Outputs 3 linear constraints (equalling constants dot_prods) using a single RLC coefficient.
    pub fn pickout_lin_constraints_from_mul_constraints(
        &self,
        constraints: &[TranscriptMulConstraint<K>],
        dot_prods: &[K; 3],
        rlc_coeff: K,
    ) -> [TranscriptLinConstraint<K>; 3] {
        let mut out_constraints: [TranscriptLinConstraint<K>; 3] =
            std::array::from_fn(|_| TranscriptLinConstraint(vec![]));

        let mut scale = K::one();
        for constraint in constraints {
            for (i, cnstr) in constraint.0.iter().enumerate() {
                out_constraints[i] += cnstr.clone() * scale;
            }
            scale *= rlc_coeff;
        }

        for (i, out_constraint) in out_constraints.iter_mut().enumerate() {
            *out_constraint -= TranscriptLinConstraint::from(dot_prods[i]); // add in the constant term
        }

        out_constraints
    }
}

/// An index into the proof transcript, represented as a (block, offset) pair.
///
/// The block index identifies which block in the jagged array, and the offset
/// identifies the position within that block.
///
/// Use `.into()` to convert to/from `[usize; 2]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TranscriptIndex<K: AbstractField> {
    inner: [usize; 2],
    _phantom: PhantomData<K>,
}

impl<K: AbstractField> std::fmt::Debug for TranscriptIndex<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscriptIndex").field("inner", &self.inner).finish()
    }
}

impl<K: AbstractField> From<[usize; 2]> for TranscriptIndex<K> {
    fn from(index: [usize; 2]) -> Self {
        Self { inner: index, _phantom: PhantomData }
    }
}

impl<K: AbstractField> From<TranscriptIndex<K>> for [usize; 2] {
    fn from(index: TranscriptIndex<K>) -> Self {
        index.inner
    }
}

/// A linear constraint represented as a vector of (coefficient, index) pairs.
///
/// The index is a pair of usizes to index into a [`ProofTranscript`] structure.
#[derive(Debug, Clone)]
pub struct TranscriptLinConstraint<K: AbstractField>(Vec<(K, TranscriptIndex<K>)>);

/// Get an expression representing the constant value K
impl<K: AbstractField> From<K> for TranscriptLinConstraint<K> {
    fn from(constant: K) -> Self {
        Self(vec![(constant, [0, 0].into())])
    }
}

/// The default is the empty constraint 0 = 0.
impl<K: AbstractField> Default for TranscriptLinConstraint<K> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<K: AbstractField + Copy> TranscriptLinConstraint<K> {
    /// Returns an iterator over the (coefficient, index) pairs in this constraint.
    pub fn iter(&self) -> impl Iterator<Item = &(K, TranscriptIndex<K>)> {
        self.0.iter()
    }

    /// Creates a constraint from a polynomial evaluation: `poly(point) = 0`.
    ///
    /// Generates: `coeff_0 + point * coeff_1 + ... + point^{n-1} * coeff_n = 0`
    pub fn poly_eval<T: Into<TranscriptLinConstraint<K>> + Clone>(poly: &[T], point: K) -> Self {
        poly.iter()
            .rev()
            .fold(TranscriptLinConstraint::default(), |acc, term| acc * point + term.clone().into())
    }

    /// Creates a constraint from `eval(1) + eval(0) = 0`.
    ///
    /// Generates: `2 * coeff_0 + coeff_1 + ... + coeff_n = 0`
    pub fn eval_one_plus_eval_zero<T: Into<TranscriptLinConstraint<K>> + Clone>(
        poly: &[T],
    ) -> Self {
        poly.iter().fold(TranscriptLinConstraint::default(), |acc, term| acc + term.clone().into())
            + poly[0].clone()
    }

    /// Creates a constraint from an MLE evaluation at point equalling zero.
    ///
    /// Assumes the input vec of elements' entries are the evaluations of the MLE on the hypercube in standard order.
    ///
    /// # Panics
    ///
    /// Requires exactly 2^{dim(Point)} many entries in `coeffs`.
    pub fn mle_eval<T: Into<TranscriptLinConstraint<K>> + Clone>(
        point: Point<K>,
        coeffs: &[T],
    ) -> Self {
        partial_lagrange_blocking(&point)
            .into_buffer()
            .into_vec()
            .into_iter()
            .zip_eq(coeffs.iter())
            .fold(TranscriptLinConstraint::default(), |acc, (coeff, index)| {
                acc + index.clone().into() * coeff
            })
    }
}

// Convert TranscriptIndex to TranscriptLinConstraint with coefficient 1
impl<K: AbstractField + Copy> From<TranscriptIndex<K>> for TranscriptLinConstraint<K> {
    fn from(index: TranscriptIndex<K>) -> Self {
        Self(vec![(K::one(), index)])
    }
}

// Addition: TranscriptLinConstraint + T where T: Into<TranscriptLinConstraint>
impl<K, T> Add<T> for TranscriptLinConstraint<K>
where
    K: AbstractField + Copy,
    T: Into<TranscriptLinConstraint<K>>,
{
    type Output = Self;

    fn add(mut self, rhs: T) -> Self::Output {
        self.0.extend(rhs.into().0);
        self
    }
}

// Addition: TranscriptIndex + T where T: Into<TranscriptLinConstraint>
impl<K, T> Add<T> for TranscriptIndex<K>
where
    K: AbstractField + Copy,
    T: Into<TranscriptLinConstraint<K>>,
{
    type Output = TranscriptLinConstraint<K>;

    fn add(self, rhs: T) -> Self::Output {
        TranscriptLinConstraint::from(self) + rhs
    }
}

// Subtraction: TranscriptLinConstraint - T where T: Into<TranscriptLinConstraint>
impl<K, T> Sub<T> for TranscriptLinConstraint<K>
where
    K: AbstractField + Copy,
    T: Into<TranscriptLinConstraint<K>>,
{
    type Output = Self;

    /// Subtracts two constraints to create an equality constraint.
    ///
    /// Returns `constraint1 - constraint2 = 0`.
    fn sub(self, other: T) -> Self::Output {
        let other = other.into();
        Self(
            self.0
                .into_iter()
                .chain(other.0.into_iter().map(|(coeff, index)| (-coeff, index)))
                .collect(),
        )
    }
}

// Subtraction: TranscriptIndex - T where T: Into<TranscriptLinConstraint>
impl<K, T> Sub<T> for TranscriptIndex<K>
where
    K: AbstractField + Copy,
    T: Into<TranscriptLinConstraint<K>>,
{
    type Output = TranscriptLinConstraint<K>;

    fn sub(self, rhs: T) -> Self::Output {
        TranscriptLinConstraint::from(self) - rhs
    }
}

// Scalar multiplication: TranscriptLinConstraint * K -> TranscriptLinConstraint
impl<K: AbstractField + Copy> Mul<K> for TranscriptLinConstraint<K> {
    type Output = Self;

    fn mul(self, scalar: K) -> Self::Output {
        let mut expr = self.0;
        for (coeff, _) in expr.iter_mut() {
            *coeff *= scalar;
        }
        Self(expr)
    }
}

// Scalar multiplication: TranscriptIndex * K -> TranscriptLinConstraint
impl<K: AbstractField + Copy> Mul<K> for TranscriptIndex<K> {
    type Output = TranscriptLinConstraint<K>;

    fn mul(self, scalar: K) -> Self::Output {
        TranscriptLinConstraint::from(self) * scalar
    }
}

// AddAssign: TranscriptLinConstraint += T where T: Into<TranscriptLinConstraint>
impl<K, T> AddAssign<T> for TranscriptLinConstraint<K>
where
    K: AbstractField + Copy,
    T: Into<TranscriptLinConstraint<K>>,
{
    fn add_assign(&mut self, rhs: T) {
        self.0.extend(rhs.into().0);
    }
}

// SubAssign: TranscriptLinConstraint -= T where T: Into<TranscriptLinConstraint>
impl<K, T> SubAssign<T> for TranscriptLinConstraint<K>
where
    K: AbstractField + Copy,
    T: Into<TranscriptLinConstraint<K>>,
{
    fn sub_assign(&mut self, rhs: T) {
        let rhs = rhs.into();
        self.0.extend(rhs.0.into_iter().map(|(coeff, idx)| (-coeff, idx)));
    }
}

// MulAssign: TranscriptLinConstraint *= K
impl<K: AbstractField + Copy> MulAssign<K> for TranscriptLinConstraint<K> {
    fn mul_assign(&mut self, scalar: K) {
        for (coeff, _) in &mut self.0 {
            *coeff = *coeff * scalar;
        }
    }
}

/// A multiplicative constraint `ab = c` where a,b,c are linear expressions in the transcript.
///
/// Represented as a triple of [`TranscriptLinConstraint`] indices for `(a, b, c)` in order.
#[derive(Debug, Clone)]
pub struct TranscriptMulConstraint<K: AbstractField>(pub [TranscriptLinConstraint<K>; 3]);

impl<K: AbstractField> TranscriptMulConstraint<K> {
    /// Creates a constraint that the product a*b is equal to c.
    pub fn from_lin_constraints(
        a: impl Into<TranscriptLinConstraint<K>>,
        b: impl Into<TranscriptLinConstraint<K>>,
        c: impl Into<TranscriptLinConstraint<K>>,
    ) -> Self {
        Self([a.into(), b.into(), c.into()])
    }
}

// ============================================================================
// PCS Integration Types
// ============================================================================

/// Index into the PCS commitment transcript.
///
/// A wrapper type for readability when distinguishing from other usize indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MleCommitmentIndex(usize);

impl MleCommitmentIndex {
    /// Creates a new MleCommitmentIndex.
    pub fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index value.
    pub fn index(&self) -> usize {
        self.0
    }
}

/// Metadata for a PCS commitment stored in the transcript.
///
/// Contains the commitment digest and structural parameters used for validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "D: Serialize", deserialize = "D: serde::de::DeserializeOwned"))]
pub struct PcsCommitmentEntry<D> {
    /// The commitment digest
    pub digest: D,
    /// Number of variables in the committed MLE
    pub num_vars: usize,
    /// Log2 of the number of polynomials in the stacking
    pub log_num_polys: usize,
}

/// An evaluation claim for a committed MLE.
///
/// Associates a commitment with an evaluation point and the claimed evaluation value.
#[derive(Clone)]
pub struct PcsEvalClaim<K, Expr> {
    /// Index of the commitment being evaluated
    pub commitment_index: MleCommitmentIndex,
    /// The evaluation point
    pub point: Point<K>,
    /// Expression representing the claimed evaluation value
    pub eval_expr: Expr,
}

/// Groups items by a key, preserving insertion order of first appearance.
///
/// Returns a `Vec` of `(key, items)` pairs where items sharing the same key
/// are collected together. The order of groups follows the first appearance
/// of each key in the input.
pub fn group_claims_by_key<T, K: PartialEq>(
    items: Vec<T>,
    key_fn: impl Fn(&T) -> K,
) -> Vec<(K, Vec<T>)> {
    let mut groups: Vec<(K, Vec<T>)> = Vec::new();
    for item in items {
        let k = key_fn(&item);
        if let Some(group) = groups.iter_mut().find(|(gk, _)| *gk == k) {
            group.1.push(item);
        } else {
            groups.push((k, vec![item]));
        }
    }
    groups
}
