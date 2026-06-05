//! Verifier for the booleanity-batched sumcheck.
//!
//! The shared types ([`BooleanityBatched`], [`BooleanityBatchedProof`],
//! [`BooleanityBatchedError`], the [`IncBranchingProgram`] used to recompute
//! `inc(z, z_new)`, the bit-side constants, etc.) live here; the prover impl
//! is in `boolean_batched_prover.rs`.

use std::array;

use crate::PREFIX_SUM_BITS;

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, ExtensionField, Field, UnivariatePolynomial};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{PartialSumcheckProof, SumcheckError};
use thiserror::Error;

/// State-vector width of the inc BP (carry × cso = 4 reachable states).
pub const INC_BP_WIDTH: usize = 4;

/// Index of the BP's *starting* state (`carry = 1, cso = 1`).  Read at the
/// end of the backward fold to recover the inc-evaluation.
pub const INC_INITIAL_STATE_INDEX: usize = 3;

/// Index of the BP's *accepting end* state (`carry = 0, cso = 1`).  Seeded
/// with weight 1 before the backward fold begins.
pub const INC_ACCEPTING_END_STATE_INDEX: usize = 2;

/// Branching-program representation of
/// `inc(i, j) = (j = i + 1) ∧ (j ≤ num_real_cols − 1)`.
///
/// `num_real_cols` is treated as a *fixed parameter* (not a variable summed
/// over with eq), so the bits of `num_real_cols` enter the transition table
/// at each layer rather than as an MLE input.
#[derive(Debug, Clone)]
pub struct IncBranchingProgram {
    pub(crate) num_vars: usize,
    pub(crate) num_real_cols: usize,
}

impl IncBranchingProgram {
    /// Build an inc BP for points of dimension `num_vars`.  Requires
    /// `1 ≤ num_real_cols ≤ 2^num_vars` so `num_real_cols − 1` fits in
    /// `num_vars` bits.
    pub fn new(num_vars: usize, num_real_cols: usize) -> Self {
        assert!(num_real_cols >= 1, "num_real_cols must be ≥ 1");
        assert!(
            num_real_cols <= 1usize << num_vars,
            "num_real_cols ({num_real_cols}) exceeds 2^num_vars (2^{num_vars})",
        );
        Self { num_vars, num_real_cols }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn num_real_cols(&self) -> usize {
        self.num_real_cols
    }

    /// Multilinear-extension evaluation of `inc` at `(i, j)`.
    ///
    /// `i` and `j` are `num_vars`-bit points; bit 0 is the LSB (stored at
    /// `Point[num_vars - 1]` per the standard `Point::from_usize` layout).
    /// Returns 1 on integer inputs satisfying both conditions, 0 otherwise;
    /// off-hypercube inputs evaluate to the unique multilinear extension.
    pub fn eval<K>(&self, i: &Point<K>, j: &Point<K>) -> K
    where
        K: AbstractField + Clone + 'static,
    {
        assert_eq!(i.dimension(), self.num_vars);
        assert_eq!(j.dimension(), self.num_vars);

        // Threshold against which `j` is compared.  Using `num_real_cols − 1`
        // matches the spec `j ≤ num_real_cols − 1`.
        let threshold = self.num_real_cols - 1;

        // Suffix DP seed: only the accepting end state has weight 1.
        let mut state: [K; INC_BP_WIDTH] = array::from_fn(|_| K::zero());
        state[INC_ACCEPTING_END_STATE_INDEX] = K::one();

        // Iterate layers MSB → LSB so the carry semantics propagate correctly
        // when read by the forward BP (which executes LSB → MSB).
        for layer in (0..self.num_vars).rev() {
            // Bit `layer` (LSB-indexed) of each point.
            let i_b = get_ith_lsb(i, layer);
            let j_b = get_ith_lsb(j, layer);
            // Fixed bit of `threshold` at this layer.
            let n_b = ((threshold >> layer) & 1) as u8;

            // 2-variable eq prefix over `(j_b, i_b)`.  Convention:
            // `blocking_partial_lagrange` maps bit `k` of the slice index to
            // `point[d − 1 − k]`, so with `point = [j_b, i_b]` the slice
            // index encodes `i_b = idx & 1`, `j_b = (idx >> 1) & 1`.
            let point: Point<K> = [j_b, i_b].into_iter().collect();
            let eq = Mle::blocking_partial_lagrange(&point);
            let eq_slice = eq.guts().as_slice();

            let mut new_state: [K; INC_BP_WIDTH] = array::from_fn(|_| K::zero());
            for (state_in_idx, new_slot) in new_state.iter_mut().enumerate() {
                let carry_in = (state_in_idx & 1) as u8;
                let cso_in = ((state_in_idx >> 1) & 1) as u8;

                // Per-input contribution to each output state.
                let mut accum: [K; INC_BP_WIDTH] = array::from_fn(|_| K::zero());

                for (input_idx, eq_val) in eq_slice.iter().enumerate().take(1usize << 2) {
                    let i_b_int = (input_idx & 1) as u8;
                    let j_b_int = ((input_idx >> 1) & 1) as u8;

                    // Carry-adder check: j = i + 1 implies j_b = i_b ⊕ carry_in
                    // and carry_out = i_b ∧ carry_in.
                    let expected_j = i_b_int ^ carry_in;
                    if j_b_int != expected_j {
                        // FAIL: drop contribution.
                        continue;
                    }
                    let carry_out = i_b_int & carry_in;

                    // Comparison update: a more-significant differing bit
                    // overrides the lower one.
                    let cso_out = match j_b_int.cmp(&n_b) {
                        std::cmp::Ordering::Less => 1u8,
                        std::cmp::Ordering::Greater => 0u8,
                        std::cmp::Ordering::Equal => cso_in,
                    };

                    let s_out_idx = (carry_out + 2 * cso_out) as usize;
                    accum[s_out_idx] += eq_val.clone();
                }

                *new_slot = accum
                    .iter()
                    .zip(state.iter())
                    .fold(K::zero(), |acc, (e, s)| acc + e.clone() * s.clone());
            }
            state = new_state;
        }

        state[INC_INITIAL_STATE_INDEX].clone()
    }
}

/// Read bit `i` (LSB-indexed) of `p`.  Returns `K::zero()` for `i ≥ dim`.
///
/// Matches the convention in `geq.rs`: `Point::from_usize` stores bit `b`
/// (`b = 0` is LSB) at index `dim − 1 − b`.
fn get_ith_lsb<K>(p: &Point<K>, i: usize) -> K
where
    K: AbstractField + Clone + 'static,
{
    let dim = p.dimension();
    if dim <= i {
        K::zero()
    } else {
        (*p[dim - 1 - i]).clone()
    }
}

/// Number of bit positions per prefix sum (32-bit prefix sums → 32 curr bits).
/// Matches `slop_jagged::jagged_assist::two_stage_jagged::PREFIX_SUM_BITS`.
pub const NUM_BITS: usize = 32;

/// `log₂(NUM_BITS)`.  The bit-side RLC point `ρ_bit` lives in `EF^LOG_NUM_BITS`,
/// so the cross-bit weights are `eq(ρ_bit, b)` for `b = 0..NUM_BITS`.  When the
/// 32 final p_b evals at z_new are RLC'd against this same `eq(ρ_bit, b)`
/// vector the result is the multilinear-extension value of the combined
/// `[NUM_BITS, 2^c]` bits MLE at the c+5-dim point `(z_new, ρ_bit)`.
pub const LOG_NUM_BITS: usize = 5;
const _: () = assert!(NUM_BITS == 1 << LOG_NUM_BITS);

/// Degree of the round univariate polynomial in the booleanity sumcheck
/// (`inc · p + α · eq · (p² + (α − 1) · p)` is degree 3 in each variable).
pub const BOOLEAN_BATCHED_DEGREE: usize = 3;

/// Output of the booleanity-batched sumcheck.  Reduces 64 evaluation claims
/// at the two-stage GKR's final point η (32 curr + 32 next at index `2(31−b)+1`
/// and `2(31−b)` respectively) to 32 evaluation claims on the curr-bit MLEs
/// at a new point `z_new`, and proves Booleanity of the 32 curr-bit MLEs.
///
/// `partial_sumcheck_proof.point_and_eval.0` is the new point `z_new`;
/// `final_evals[b] = p_b(z_new)` for `b = 0..NUM_BITS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanityBatchedProof<F> {
    pub partial_sumcheck_proof: PartialSumcheckProof<F>,
    pub final_evals: Vec<F>,
}

impl<F: AbstractField> BooleanityBatchedProof<F> {
    /// Structurally-valid dummy proof for downstream stub construction
    /// (witness conversion, recursion circuit, etc.).  Not a sound proof.
    pub fn dummy(num_variables: usize) -> Self {
        let degree = BOOLEAN_BATCHED_DEGREE;
        let zero_poly = UnivariatePolynomial::zero(degree);
        Self {
            partial_sumcheck_proof: PartialSumcheckProof {
                univariate_polys: vec![zero_poly; num_variables],
                claimed_sum: F::zero(),
                point_and_eval: (Point::from(vec![F::zero(); num_variables]), F::zero()),
            },
            final_evals: vec![F::zero(); NUM_BITS],
        }
    }
}

#[derive(Debug, Error)]
pub enum BooleanityBatchedError<F: Field> {
    #[error("inner sumcheck error: {0}")]
    SumcheckError(SumcheckError),
    #[error("incorrect proof shape")]
    IncorrectShape,
    #[error("final evaluation check failed: expected {0}, got {1}")]
    FinalEvalMismatch(F, F),
}

/// Per-column-shape config for the booleanity-batched sumcheck.  Holds the two
/// integer parameters shared by prove and verify; the runtime polynomials,
/// challenges, and challenger are method args.
#[derive(Debug, Clone, Copy)]
pub struct BooleanityBatched {
    /// Number of "real" columns = `num_real_pairs`.
    pub num_real_cols: usize,
    /// `prefix_sums[num_real_pairs]` — the max prefix-sum value.
    pub max_prefix_sum: usize,
}

impl BooleanityBatched {
    pub const fn new(num_real_cols: usize, max_prefix_sum: usize) -> Self {
        Self { num_real_cols, max_prefix_sum }
    }
}

/// Split a two-stage GKR proof's `final_evals` into per-bit (v_next, v_curr)
/// using the booleanity convention `v_curr[b] = final_evals[2(PREFIX_SUM_BITS −
/// 1 − b) + 1]`, `v_next[b] = final_evals[2(PREFIX_SUM_BITS − 1 − b)]`.
pub fn split_two_stage_finals<EF: Copy>(two_stage_finals: &[EF]) -> (Vec<EF>, Vec<EF>) {
    let v_curr: Vec<EF> =
        (0..NUM_BITS).map(|b| two_stage_finals[2 * (PREFIX_SUM_BITS - 1 - b) + 1]).collect();
    let v_next: Vec<EF> =
        (0..NUM_BITS).map(|b| two_stage_finals[2 * (PREFIX_SUM_BITS - 1 - b)]).collect();
    (v_next, v_curr)
}

impl BooleanityBatched {
    /// Verify the booleanity-batched sumcheck and recover the 32 evaluation
    /// claims on `p_b(z_new)`.  Returns the final point `z_new` and the 32
    /// claims.
    ///
    /// The verifier must independently compute the same `max_prefix_sum` and
    /// `num_real_cols` from the proof's `row_counts_and_column_counts` and
    /// pass them via [`Self::new`].
    pub fn verify<F, EF, Chal>(
        &self,
        proof: &BooleanityBatchedProof<EF>,
        z: &Point<EF>,
        two_stage_finals: &[EF],
        alpha: EF,
        rho_bit: &Point<EF>,
        challenger: &mut Chal,
    ) -> Result<(Point<EF>, EF), BooleanityBatchedError<EF>>
    where
        F: Field,
        EF: ExtensionField<F>,
        Chal: FieldChallenger<F>,
    {
        let Self { num_real_cols, max_prefix_sum } = *self;
        if proof.final_evals.len() != NUM_BITS || two_stage_finals.len() != 2 * NUM_BITS {
            return Err(BooleanityBatchedError::IncorrectShape);
        }
        if rho_bit.dimension() != LOG_NUM_BITS {
            return Err(BooleanityBatchedError::IncorrectShape);
        }
        let (v_next, v_curr) = split_two_stage_finals(two_stage_finals);

        let c = z.dimension();
        let eq_rho = bit_rlc_table(rho_bit);
        let eq_at_boundary = eq_eval_at_int::<F, EF>(z, num_real_cols - 1);
        let alpha_sq = alpha * alpha;

        let lambda: Vec<EF> = (0..NUM_BITS)
            .map(|b| if (max_prefix_sum >> b) & 1 == 1 { EF::one() } else { EF::zero() })
            .collect();

        let expected_initial_claim: EF = (0..NUM_BITS)
            .map(|b| eq_rho[b] * (v_next[b] + alpha_sq * v_curr[b] - lambda[b] * eq_at_boundary))
            .sum();
        if expected_initial_claim != proof.partial_sumcheck_proof.claimed_sum {
            return Err(BooleanityBatchedError::FinalEvalMismatch(
                expected_initial_claim,
                proof.partial_sumcheck_proof.claimed_sum,
            ));
        }

        slop_sumcheck::partially_verify_sumcheck_proof(
            &proof.partial_sumcheck_proof,
            challenger,
            c,
            BOOLEAN_BATCHED_DEGREE,
        )
        .map_err(BooleanityBatchedError::SumcheckError)?;

        // At z_new, recompute the polynomial F(z_new) using the prover's claimed
        // 32 final_evals and verify it matches the sumcheck's reduced eval.
        let z_new = proof.partial_sumcheck_proof.point_and_eval.0.clone();
        let inc_zn = IncBranchingProgram::new(c, num_real_cols).eval(z, &z_new);
        let eq_zn = Mle::full_lagrange_eval(z, &z_new);

        let sum_p: EF = (0..NUM_BITS).map(|b| eq_rho[b] * proof.final_evals[b]).sum();
        let sum_p_sq: EF =
            (0..NUM_BITS).map(|b| eq_rho[b] * proof.final_evals[b] * proof.final_evals[b]).sum();

        let aa_minus_a = alpha_sq - alpha;
        let expected_final = (inc_zn + aa_minus_a * eq_zn) * sum_p + alpha * eq_zn * sum_p_sq;
        if expected_final != proof.partial_sumcheck_proof.point_and_eval.1 {
            return Err(BooleanityBatchedError::FinalEvalMismatch(
                expected_final,
                proof.partial_sumcheck_proof.point_and_eval.1,
            ));
        }

        // The "implied" single eval claim on the combined `[NUM_BITS, 2^c]`
        // bits MLE at the c+5-dim point `(z_new, ρ_bit)` is the same eq-RLC of
        // the 32 per-bit finals: `Σ_b eq(ρ,b) · p_b(z_new) = P(z_new, ρ_bit)`.
        // We've already computed it as `sum_p` above.
        let combined_point: Point<EF> =
            z_new.iter().copied().chain(rho_bit.iter().copied()).collect::<Vec<_>>().into();
        Ok((combined_point, sum_p))
    }
}

/// `[eq(rho_bit, b)]_{b = 0..NUM_BITS}`, length `NUM_BITS`.  Entry `b` is the
/// multilinear-extension weight `eq` of the 5-bit point `rho_bit` against the
/// integer `b`, packing `bit_0(b)` as the LSB.  Building this via
/// `Mle::blocking_partial_lagrange` aligns with the prefix-sum bit indexing
/// used elsewhere in this file (`λ_b`, `v_curr[b]`, `v_next[b]`).
#[inline]
pub(crate) fn bit_rlc_table<EF: Field>(rho_bit: &Point<EF>) -> Vec<EF> {
    debug_assert_eq!(rho_bit.dimension(), LOG_NUM_BITS);
    Mle::blocking_partial_lagrange(rho_bit).guts().as_slice().to_vec()
}

/// Evaluate `eq(z, integer_j)` for an integer `integer_j` interpreted as a
/// `c`-bit point.  Uses `full_lagrange_eval`, which is `O(c)` and avoids the
/// `O(2^c)` `partial_lagrange` table.
pub(crate) fn eq_eval_at_int<F, EF>(z: &Point<EF>, integer_j: usize) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let c = z.dimension();
    let boundary: Point<F> = Point::from_usize(integer_j, c);
    Mle::full_lagrange_eval(&boundary, z)
}
