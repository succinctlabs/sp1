//! Example: ZK zerocheck proving that the pointwise product of two MLEs equals a third.
//!
//! Protocol:
//! 1. Generate random extension field MLEs p, q and compute r = p * q pointwise
//! 2. Commit p, q, r via PCS
//! 3. Verifier samples a random point z_0
//! 4. Build the composition f(x) = eq(x, z_0) * (p(x) * q(x) - r(x))
//! 5. Use sumcheck to prove sum of f over the hypercube is 0, producing eval claims at z
//! 6. Verify eq(z, z_0) (cheap for verifier)
//! 7. Prove p(z), q(z), r(z) via PCS

use itertools::Itertools;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, UnivariatePolynomial,
};
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::protocols::sumcheck::{SumcheckParam, SumcheckView};
use slop_veil::zk::stacked_pcs::{initialize_zk_prover_and_verifier, StackedPcsZkProverCtx};
use slop_veil::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type F = <GC as IopCtx>::F;
type EF = <GC as IopCtx>::EF;
type MK = Poseidon2KoalaBear16Prover;

const LOG_NUM_POLYNOMIALS: u32 = 8;
const LOG_ENCODING_VARS: u32 = 16;
const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + LOG_ENCODING_VARS;

// ============================================================================
// Zerocheck composition polynomial: f(x) = eq(z_0, x) * (p(x) * q(x) - r(x))
// ============================================================================

/// The polynomial f(x) = eq(z_0, x) * (p(x) * q(x) - r(x)) for the zerocheck sumcheck.
///
/// Modeled after `ProdcheckPoly` in the Spartan crate. The eq MLE is "succinct" in that
/// the verifier can compute eq(z, z_0) in O(n) time given both points.
struct ZerocheckPoly {
    eq_z0: Mle<EF>,
    p: Mle<EF>,
    q: Mle<EF>,
    r: Mle<EF>,
}

impl SumcheckPolyBase for ZerocheckPoly {
    fn num_variables(&self) -> u32 {
        self.p.num_variables()
    }
}

impl ComponentPoly<EF> for ZerocheckPoly {
    fn get_component_poly_evals(&self) -> Vec<EF> {
        assert_eq!(self.num_variables(), 0, "queried before reduction was finished");
        let empty_point = Point::<EF>::new(vec![].into());
        vec![
            self.p.eval_at(&empty_point).to_vec()[0],
            self.q.eval_at(&empty_point).to_vec()[0],
            self.r.eval_at(&empty_point).to_vec()[0],
        ]
    }
}

impl SumcheckPoly<EF> for ZerocheckPoly {
    fn fix_last_variable(self, alpha: EF) -> Self {
        Self {
            eq_z0: self.eq_z0.fix_last_variable(alpha),
            p: self.p.fix_last_variable(alpha),
            q: self.q.fix_last_variable(alpha),
            r: self.r.fix_last_variable(alpha),
        }
    }

    fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        assert!(claim.is_some());

        // f(x) = eq(z_0, x) * (p(x) * q(x) - r(x)) is degree 3 in each variable.
        // We need 4 evaluation points to interpolate a degree-3 univariate.
        let zero = EF::zero();
        let one = EF::one();
        let m_one = -one;
        let two = one + one;

        let mut eval_zero = EF::zero();
        let mut eval_m_one = EF::zero();
        let mut eval_two = EF::zero();

        // Iterate over pairs (c_0 = evals at even index, c_1 = evals at odd index)
        // The last variable selects between c_0 (at 0) and c_1 (at 1).
        // Linear interpolation: val(t) = c_0 + t * (c_1 - c_0) = c_0 * (1-t) + c_1 * t
        for (c_0, c_1) in self
            .eq_z0
            .hypercube_iter()
            .zip(self.p.hypercube_iter())
            .zip(self.q.hypercube_iter())
            .zip(self.r.hypercube_iter())
            .map(|(((eq, p), q), r)| (eq[0], p[0], q[0], r[0]))
            .tuples()
        {
            let eq_0 = c_0.0;
            let eq_1 = c_1.0;
            let p_0 = c_0.1;
            let p_1 = c_1.1;
            let q_0 = c_0.2;
            let q_1 = c_1.2;
            let r_0 = c_0.3;
            let r_1 = c_1.3;

            // eval at t=0: eq_0 * (p_0 * q_0 - r_0)
            eval_zero += eq_0 * (p_0 * q_0 - r_0);

            // Precompute differences for evaluating at other points
            let d_eq = eq_0 - eq_1;
            let d_p = p_0 - p_1;
            let d_q = q_0 - q_1;
            let d_r = r_0 - r_1;

            // eval at t=-1: (eq_0 + d_eq) * ((p_0 + d_p) * (q_0 + d_q) - (r_0 + d_r))
            eval_m_one += (eq_0 + d_eq) * ((p_0 + d_p) * (q_0 + d_q) - (r_0 + d_r));

            // eval at t=2: (eq_1 - d_eq) * ((p_1 - d_p) * (q_1 - d_q) - (r_1 - d_r))
            eval_two += (eq_1 - d_eq) * ((p_1 - d_p) * (q_1 - d_q) - (r_1 - d_r));
        }

        // eval at t=1 is derived from the claim: claim = eval_zero + eval_one
        let eval_one = claim.unwrap() - eval_zero;

        interpolate_univariate_polynomial(
            &[zero, one, m_one, two],
            &[eval_zero, eval_one, eval_m_one, eval_two],
        )
    }
}

impl SumcheckPolyFirstRound<EF> for ZerocheckPoly {
    type NextRoundPoly = Self;

    fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1);
        self.fix_last_variable(alpha)
    }

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1);
        self.sum_as_poly_in_last_variable(claim)
    }
}

// ============================================================================
// Data generation
// ============================================================================

/// Generate a random EF MLE and its base field version for committing.
fn generate_random_ef_mle(rng: &mut impl Rng, num_vars: u32) -> (Mle<F>, Mle<EF>) {
    let base_mle = Mle::<F>::rand(rng, 1, num_vars);
    let ef_data: Vec<EF> = base_mle.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let ef_mle = Mle::new(RowMajorMatrix::new(ef_data, 1).into());
    (base_mle, ef_mle)
}

/// Compute pointwise product of two EF MLEs.
fn pointwise_product(p: &Mle<EF>, q: &Mle<EF>) -> Mle<EF> {
    let p_data = p.guts().as_slice();
    let q_data = q.guts().as_slice();
    let r_data: Vec<EF> = p_data.iter().zip(q_data.iter()).map(|(&a, &b)| a * b).collect();
    Mle::new(RowMajorMatrix::new(r_data, 1).into())
}

/// Convert an EF MLE to a base field MLE (truncating to the base field part).
/// This works because our random MLEs were generated as base field elements lifted to EF.
fn ef_mle_to_base(mle: &Mle<EF>) -> Mle<F> {
    let data: Vec<F> =
        mle.guts().as_slice().iter().map(|x| AbstractExtensionField::as_base_slice(x)[0]).collect();
    Mle::new(RowMajorMatrix::new(data, 1).into())
}

// ============================================================================
// Protocol read/constrain functions (shared by prover, verifier, and mask counter)
// ============================================================================

struct ZerocheckView<C: ConstraintCtx> {
    p_oracle: C::MleOracle,
    q_oracle: C::MleOracle,
    r_oracle: C::MleOracle,
    z_0: Point<C::Challenge>,
    sumcheck_view: SumcheckView<C>,
}

fn zerocheck_read<C: ReadingCtx>(ctx: &mut C) -> ZerocheckView<C> {
    // Read the three PCS commitments
    let p_oracle = ctx.read_oracle(LOG_ENCODING_VARS, LOG_NUM_POLYNOMIALS).unwrap();
    let q_oracle = ctx.read_oracle(LOG_ENCODING_VARS, LOG_NUM_POLYNOMIALS).unwrap();
    let r_oracle = ctx.read_oracle(LOG_ENCODING_VARS, LOG_NUM_POLYNOMIALS).unwrap();

    // Read the zerocheck random point z_0
    let z_0 = ctx.sample_point(NUM_VARIABLES);

    // Read the sumcheck proof.
    // f(x) = eq(z_0, x) * (p(x) * q(x) - r(x)) has degree 3, with 3 component evals (p, q, r).
    let param = SumcheckParam::with_component_evals(NUM_VARIABLES, 3, 3);
    let sumcheck_view = param.read(ctx).unwrap();

    ZerocheckView { p_oracle, q_oracle, r_oracle, z_0, sumcheck_view }
}

fn zerocheck_build_constraints<C: ConstraintCtx<Challenge = EF>>(
    ctx: &mut C,
    view: ZerocheckView<C>,
) {
    let z = Point::from(view.sumcheck_view.point.clone());

    let p_eval = view.sumcheck_view.component_evals[0].clone();
    let q_eval = view.sumcheck_view.component_evals[1].clone();
    let r_eval = view.sumcheck_view.component_evals[2].clone();

    // Constraint: claimed_eval == eq(z, z_0) * (p(z) * q(z) - r(z))
    //
    // eq(z, z_0) is computable in O(n) by the verifier since z (sumcheck challenges)
    // and z_0 (Fiat-Shamir) are both known field elements.
    let eq_eval = Mle::<EF>::full_lagrange_eval(&view.z_0, &z);

    // Express as a single polynomial constraint:
    //   eq(z, z_0) * (p(z) * q(z) - r(z)) - claimed_eval = 0
    let pq_minus_r = p_eval.clone() * q_eval.clone() - r_eval.clone();
    let constraint = pq_minus_r * eq_eval - view.sumcheck_view.claimed_eval.clone();
    ctx.assert_zero(constraint);

    // Constraint 3: PCS evaluation claims for p, q, r at point z
    ctx.assert_mle_multi_eval(
        vec![(view.p_oracle, p_eval), (view.q_oracle, q_eval), (view.r_oracle, r_eval)],
        z,
    );

    // Emit sumcheck round-consistency constraints
    view.sumcheck_view.build_constraints(ctx).unwrap();
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    eprintln!("Generating random MLEs (num_variables = {NUM_VARIABLES})...");

    // Generate random EF MLEs p, q and compute r = p * q pointwise
    let (p_base, p_ef) = generate_random_ef_mle(&mut rng, NUM_VARIABLES);
    let (q_base, q_ef) = generate_random_ef_mle(&mut rng, NUM_VARIABLES);
    let r_ef = pointwise_product(&p_ef, &q_ef);
    let r_base = ef_mle_to_base(&r_ef);

    // Compute mask length
    let mask_length = compute_mask_length::<GC, _>(zerocheck_read, |data, ctx| {
        zerocheck_build_constraints(ctx, data)
    });
    eprintln!("Mask length: {mask_length}");

    // Initialize PCS (3 commitments)
    let (pcs_prover, pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(3, LOG_ENCODING_VARS);

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        let now = std::time::Instant::now();

        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs(mask_length, pcs_prover, &mut rng);

        // Commit p, q, r
        let p_oracle = ctx.commit_mle(p_base, LOG_NUM_POLYNOMIALS, &mut rng).unwrap();
        let q_oracle = ctx.commit_mle(q_base, LOG_NUM_POLYNOMIALS, &mut rng).unwrap();
        let r_oracle = ctx.commit_mle(r_base, LOG_NUM_POLYNOMIALS, &mut rng).unwrap();

        // Sample the zerocheck random point z_0
        let z_0: Point<EF> = ctx.sample_point(NUM_VARIABLES);

        // Build the zerocheck composition polynomial
        let eq_z0 = Mle::<EF>::partial_lagrange(&z_0);
        let zerocheck_poly =
            ZerocheckPoly { eq_z0, p: p_ef.clone(), q: q_ef.clone(), r: r_ef.clone() };

        // Run sumcheck on f(x) = eq(z_0, x) * (p(x) * q(x) - r(x)) with claim = 0
        let param = SumcheckParam::with_component_evals(NUM_VARIABLES, 3, 3);
        let sumcheck_view = param.prove(zerocheck_poly, &mut ctx, EF::zero());

        // Build constraints using the shared function
        let full_prover_view = ZerocheckView { p_oracle, q_oracle, r_oracle, z_0, sumcheck_view };
        zerocheck_build_constraints(&mut ctx, full_prover_view);

        let proof = ctx.prove(&mut rng);
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let now = std::time::Instant::now();

        let mut ctx = ZkVerifierCtx::init(proof, Some(pcs_verifier));
        let verifier_view = zerocheck_read(&mut ctx);
        zerocheck_build_constraints(&mut ctx, verifier_view);
        ctx.verify().expect("verification failed");

        eprintln!("Verifier time: {:?}", now.elapsed());
    }

    eprintln!("\n=== PASSED ===");
}
