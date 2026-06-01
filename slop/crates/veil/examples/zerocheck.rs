//! Example: zerocheck proving the pointwise product of two MLEs equals a third,
//! run against two backends.
//!
//! Protocol:
//! 1. Generate random extension-field MLEs p, q and compute r = p * q pointwise.
//! 2. Commit p, q, r via PCS.
//! 3. Sample a random point z_0.
//! 4. Build the composition f(x) = eq(x, z_0) * (p(x) * q(x) - r(x)).
//! 5. Sumcheck over f with input claim 0, producing component evals at point z.
//! 6. Tie the component evals to p(z), q(z), r(z) via PCS openings.
//!
//! Two functions encode the protocol:
//!
//! - `zerocheck_prove`: prover-only — commit + sample + send. No constraints,
//!   no `View`. Its job is purely to populate the transcript (and, on a prover
//!   context, the replay log).
//! - `zerocheck_verify`: reads-and-constrains in one pass. Generic over any
//!   `ReadingCtx`, so it runs unchanged on the verifier *and* on the prover —
//!   the prover context implements a non-challenger-touching replay
//!   `ReadingCtx` that lets it replay its own transcript through the same body
//!   the verifier uses.
//!
//! Driver: `prove(); verify()` on the prover, `verify()` on the verifier.

use itertools::Itertools;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, UnivariatePolynomial,
};
use slop_challenger::IopCtx;
use slop_commit::Message;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};
use slop_veil::compiler::{ReadingCtx, SendingCtx};
use slop_veil::protocols::sumcheck::{SumcheckInputClaim, SumcheckParam};
use slop_veil::transparent::{
    initialize_transparent_prover_and_verifier, TransparentProverCtx, TransparentVerifierCtx,
};
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
// (identical to `zerocheck.rs`)
// ============================================================================

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

        let zero = EF::zero();
        let one = EF::one();
        let m_one = -one;
        let two = one + one;

        let mut eval_zero = EF::zero();
        let mut eval_m_one = EF::zero();
        let mut eval_two = EF::zero();

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

            eval_zero += eq_0 * (p_0 * q_0 - r_0);

            let d_eq = eq_0 - eq_1;
            let d_p = p_0 - p_1;
            let d_q = q_0 - q_1;
            let d_r = r_0 - r_1;

            eval_m_one += (eq_0 + d_eq) * ((p_0 + d_p) * (q_0 + d_q) - (r_0 + d_r));
            eval_two += (eq_1 - d_eq) * ((p_1 - d_p) * (q_1 - d_q) - (r_1 - d_r));
        }

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
// Data generation (identical to `zerocheck.rs`)
// ============================================================================

fn generate_random_ef_mle(rng: &mut impl Rng, num_vars: u32) -> (Mle<F>, Mle<EF>) {
    let base_mle = Mle::<F>::rand(rng, 1, num_vars);
    let ef_data: Vec<EF> = base_mle.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let ef_mle = Mle::new(RowMajorMatrix::new(ef_data, 1).into());
    (base_mle, ef_mle)
}

fn pointwise_product(p: &Mle<EF>, q: &Mle<EF>) -> Mle<EF> {
    let p_data = p.guts().as_slice();
    let q_data = q.guts().as_slice();
    let r_data: Vec<EF> = p_data.iter().zip(q_data.iter()).map(|(&a, &b)| a * b).collect();
    Mle::new(RowMajorMatrix::new(r_data, 1).into())
}

fn ef_mle_to_base(mle: &Mle<EF>) -> Mle<F> {
    let data: Vec<F> =
        mle.guts().as_slice().iter().map(|x| AbstractExtensionField::as_base_slice(x)[0]).collect();
    Mle::new(RowMajorMatrix::new(data, 1).into())
}

// ============================================================================
// Generic protocol code
// ============================================================================

/// Prover-only entry point: commit p, q, r; sample `z_0`; build the zerocheck
/// composition polynomial; run sumcheck with the constant-zero input claim.
///
/// Emits no constraints and returns no view — its sole job is to populate the
/// transcript (and, on a prover context, the replay log). Constraints are built
/// later by [`zerocheck_verify`], which the prover replays.
#[allow(clippy::too_many_arguments)]
fn zerocheck_prove<C, RNG>(
    ctx: &mut C,
    p_base: Mle<C::Field>,
    q_base: Mle<C::Field>,
    r_base: Mle<C::Field>,
    p_ef: Mle<EF>,
    q_ef: Mle<EF>,
    r_ef: Mle<EF>,
    rng: &mut RNG,
) where
    C: SendingCtx<Challenge = EF, Extension = EF>,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    ctx.commit_mle(Message::from(p_base), rng).expect("commit p failed");
    ctx.commit_mle(Message::from(q_base), rng).expect("commit q failed");
    ctx.commit_mle(Message::from(r_base), rng).expect("commit r failed");

    let z_0: Point<EF> = ctx.sample_point(NUM_VARIABLES);

    let eq_z0 = Mle::<EF>::partial_lagrange(&z_0);
    let zerocheck_poly = ZerocheckPoly { eq_z0, p: p_ef, q: q_ef, r: r_ef };

    let sumcheck_in_claim = SumcheckInputClaim::zero();
    SumcheckParam::with_component_evals(NUM_VARIABLES, 3, 3).prove(
        &sumcheck_in_claim,
        zerocheck_poly,
        ctx,
    );
}

/// Unified read+constrain pass. Reads the three committed oracles, samples
/// `z_0`, runs the sumcheck via [`SumcheckParam::verify`] (which reads *and*
/// constrains), then ties the reduced claim to `eq(z, z_0) * (p*q - r)` and
/// registers the PCS opening claims — all in one function, generic over any
/// `ReadingCtx`. Used by both the verifier and the (replaying) prover.
fn zerocheck_verify<C: ReadingCtx<Challenge = EF>>(ctx: &mut C) {
    let p_oracle = ctx.read_oracle(NUM_VARIABLES).unwrap();
    let q_oracle = ctx.read_oracle(NUM_VARIABLES).unwrap();
    let r_oracle = ctx.read_oracle(NUM_VARIABLES).unwrap();

    let z_0 = ctx.sample_point(NUM_VARIABLES);

    // f(x) = eq(z_0, x) * (p(x) * q(x) - r(x)): degree 3, 3 component evals (p, q, r).
    let sumcheck_in_claim = SumcheckInputClaim::zero();
    let out_claim = SumcheckParam::with_component_evals(NUM_VARIABLES, 3, 3)
        .verify(&sumcheck_in_claim, ctx)
        .expect("sumcheck verify failed");

    let z = Point::from(out_claim.point.clone());
    let p_eval = out_claim.component_evals[0][0].clone();
    let q_eval = out_claim.component_evals[0][1].clone();
    let r_eval = out_claim.component_evals[0][2].clone();

    // Constraint: claimed_eval == eq(z, z_0) * (p(z) * q(z) - r(z)).
    let eq_eval = Mle::<EF>::full_lagrange_eval(&z_0, &z);
    let pq_minus_r = p_eval.clone() * q_eval.clone() - r_eval.clone();
    let constraint = pq_minus_r * eq_eval - out_claim.claimed_eval.clone();
    ctx.assert_zero(constraint).unwrap();

    // PCS evaluation claims for p, q, r at the shared point z (one multi-eval group).
    ctx.assert_mle_multi_eval(vec![(p_oracle, p_eval), (q_oracle, q_eval), (r_oracle, r_eval)], z);
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    eprintln!("Generating random MLEs (num_variables = {NUM_VARIABLES})...");
    let (p_base, p_ef) = generate_random_ef_mle(&mut rng, NUM_VARIABLES);
    let (q_base, q_ef) = generate_random_ef_mle(&mut rng, NUM_VARIABLES);
    let r_ef = pointwise_product(&p_ef, &q_ef);
    let r_base = ef_mle_to_base(&r_ef);

    // ZK backend.
    eprintln!("\n=== ZK BACKEND ===");
    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(3, LOG_ENCODING_VARS);

    let zk_proof = {
        let now = std::time::Instant::now();
        let mask_length = compute_mask_length::<GC>(LOG_ENCODING_VARS, zerocheck_verify);
        eprintln!("Mask length: {mask_length}");
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");
        zerocheck_prove(
            &mut pctx,
            p_base.clone(),
            q_base.clone(),
            r_base.clone(),
            p_ef.clone(),
            q_ef.clone(),
            r_ef.clone(),
            &mut rng,
        );
        // Prover replays the SAME verify body to build constraints.
        zerocheck_verify(&mut pctx);
        let proof = pctx.prove(&mut rng).expect("zk prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = ZkVerifierCtx::init(zk_proof, Some(zk_pcs_verifier));
        zerocheck_verify(&mut vctx);
        vctx.verify().expect("zk verification failed");
    }
    eprintln!("ZK backend: PASSED");

    // Transparent backend.
    eprintln!("\n=== TRANSPARENT BACKEND ===");
    let (stacked_prover, stacked_verifier) = initialize_transparent_prover_and_verifier::<GC, MK>(
        3,
        LOG_ENCODING_VARS,
        LOG_NUM_POLYNOMIALS,
    );

    let transparent_proof = {
        let now = std::time::Instant::now();
        let mut pctx: TransparentProverCtx<GC, MK> =
            TransparentProverCtx::initialize(stacked_prover);
        zerocheck_prove(&mut pctx, p_base, q_base, r_base, p_ef, q_ef, r_ef, &mut rng);
        zerocheck_verify(&mut pctx);
        let proof = pctx.prove(&mut rng).expect("transparent prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(transparent_proof, Some(stacked_verifier));
        zerocheck_verify(&mut vctx);
        vctx.verify().expect("transparent verification failed");
    }
    eprintln!("Transparent backend: PASSED");

    eprintln!("\n=== ALL PASSED ===");
}
