use std::cell::RefCell;
use std::ops::{Add, Mul, Sub};
use std::rc::Rc;

use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_challenger::IopCtx;

use super::constraints::{ConstraintContextInnerExt, ZkCnstrAndReadingCtxInner};
use super::ZkIopCtx;
use crate::compiler::TranscriptReadError;

/// Computes the mask length by running the protocol's read and constraint
/// building logic on a counting context.
///
/// This abstracts the common pattern of creating a `MaskCounterContext`,
/// running `read_all` and `build_all_constraints` on it, then extracting the count.
///
/// # Arguments
/// * `read_all` - Closure that reads proof data from the context (mirrors prover's transcript writes), possibly using global params
/// * `build_all` - Closure that builds constraints using the read data and possibly global params
///
/// # Example
/// ```ignore
/// let masks_length = compute_mask_length::<GC, _, _, _>(
///     |ctx| read_all(ctx, num_vars, log_num_polys),
///     |data, ctx| build_all_constraints(data, &point, ctx),
/// );
/// ```
pub fn compute_mask_length<GC, T, R, B>(read_all: R, build_all: B) -> usize
where
    GC: ZkIopCtx,
    R: FnOnce(&mut MaskCounterContext<GC>) -> T,
    B: FnOnce(T, &mut MaskCounterContext<GC>),
{
    let mut mask_counter = MaskCounterContext::<GC>::default();
    let data = read_all(&mut mask_counter);
    build_all(data, &mut mask_counter);
    mask_counter.count()
}

/// A counting context that tracks the number of transcript reads.
///
/// This is useful for determining the mask size needed for a ZK proof
/// without actually running the full prover/verifier.
#[derive(Clone)]
pub struct MaskCounterContext<GC: IopCtx> {
    counter: Rc<RefCell<usize>>,
    challenger: Rc<RefCell<GC::Challenger>>,
    /// Stored PCS commitment parameters for computing mask counts in `assert_mle_eval`.
    pcs_commitments: Rc<RefCell<Vec<usize>>>,
}

impl<GC: IopCtx> MaskCounterContext<GC> {
    /// Creates a new counting context with the counter starting at zero.
    fn new() -> Self {
        Self {
            counter: Rc::new(RefCell::new(0)),
            challenger: Rc::new(RefCell::new(GC::default_challenger())),
            pcs_commitments: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Returns the current count.
    pub fn count(&self) -> usize {
        *self.counter.borrow()
    }
}

impl<GC: IopCtx> Default for MaskCounterContext<GC> {
    fn default() -> Self {
        Self::new()
    }
}

impl<GC: IopCtx> AsRef<MaskCounterContext<GC>> for MaskCounterContext<GC> {
    fn as_ref(&self) -> &MaskCounterContext<GC> {
        self
    }
}

impl<GC: IopCtx> std::fmt::Debug for MaskCounterContext<GC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountingContext").field("counter", &self.counter).finish()
    }
}

// ============================================================================
// Arithmetic trait implementations for CountingContext
// ============================================================================

impl<GC: IopCtx> Add for MaskCounterContext<GC> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self::Output {
        self
    }
}

impl<GC: IopCtx, K: AbstractField + Copy> Add<K> for MaskCounterContext<GC> {
    type Output = Self;

    fn add(self, _rhs: K) -> Self::Output {
        self
    }
}

impl<GC: IopCtx> Sub for MaskCounterContext<GC> {
    type Output = Self;

    fn sub(self, _rhs: Self) -> Self::Output {
        self
    }
}

impl<GC: IopCtx, K: AbstractField + Copy> Sub<K> for MaskCounterContext<GC> {
    type Output = Self;

    fn sub(self, _rhs: K) -> Self::Output {
        self
    }
}

impl<GC: IopCtx> Mul for MaskCounterContext<GC> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, _rhs: Self) -> Self::Output {
        *self.counter.borrow_mut() += 1;
        self
    }
}

impl<GC: IopCtx, K: AbstractField + Copy> Mul<K> for MaskCounterContext<GC> {
    type Output = Self;

    fn mul(self, _rhs: K) -> Self::Output {
        self
    }
}

impl<GC: IopCtx> std::ops::Neg for MaskCounterContext<GC> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

// ============================================================================
// ConstraintContext implementation
// ============================================================================

impl<GC: ZkIopCtx> ConstraintContextInnerExt<GC::EF> for MaskCounterContext<GC> {
    type Expr = MaskCounterContext<GC>;

    fn assert_zero(&mut self, _expr: Self::Expr) {}

    fn assert_a_times_b_equals_c(&mut self, _a: Self::Expr, _b: Self::Expr, _c: Self::Expr) {}

    fn cst(&mut self, _value: GC::EF) -> Self::Expr {
        self.clone()
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(super::MleCommitmentIndex, Self::Expr)>,
        _point: super::Point<GC::EF>,
    ) {
        let pcs_commitments = self.pcs_commitments.borrow();
        // Each claim corresponds to evaluating a commitment at a point, which requires reading
        // the data column evaluations.
        for (commitment_index, _) in claims.iter() {
            let log_num_polys = pcs_commitments[commitment_index.index()];
            let num_data = 1 << log_num_polys;
            *self.counter.borrow_mut() += num_data;
        }
        // Account for mask column evaluations (only once, from the first commitment)
        *self.counter.borrow_mut() += GC::EF::D;
    }
}

impl<GC: ZkIopCtx> ZkCnstrAndReadingCtxInner<GC> for MaskCounterContext<GC> {
    fn read_next(&mut self, num: usize) -> Result<Vec<Self::Expr>, TranscriptReadError> {
        // Increment the counter by the number of elements read
        *self.counter.borrow_mut() += num;

        // Return placeholder expressions. The counter never fails — it isn't bounded by
        // any real transcript — so this is infallible.
        Ok(vec![self.clone(); num])
    }

    fn challenger(&mut self) -> std::cell::RefMut<'_, GC::Challenger> {
        self.challenger.borrow_mut()
    }

    fn read_next_pcs_commitment(
        &mut self,
        _num_vars: usize,
        log_num_polys: usize,
    ) -> Option<super::MleCommitmentIndex> {
        // Store the parameters for later use in assert_mle_eval
        let mut pcs_commitments = self.pcs_commitments.borrow_mut();
        let index = pcs_commitments.len();
        pcs_commitments.push(log_num_polys);
        Some(super::MleCommitmentIndex::new(index))
    }
}
