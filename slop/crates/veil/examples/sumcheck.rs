//! Example: ZK sumcheck using the public VEIL interface.
//!
//! Demonstrates the full prove/verify flow:
//! 1. Generate a random MLE and compute its hypercube sum
//! 2. Prover sends sumcheck messages via `ZkProverCtx`
//! 3. Verifier reads and checks via `ZkVerifierCtx` + compiler `SumcheckParam`

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_algebra::{Dorroh, TwoAdicField};
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::Mle;
use slop_sumcheck::{SumcheckPoly, SumcheckPolyFirstRound};
use slop_veil::compiler::sumcheck::{SumcheckParam, SumcheckView};
use slop_veil::compiler::ReadingCtx;
use slop_veil::zk::{
    compute_mask_length, ProverTranscriptElement, ZkIopCtx, ZkMerkleizer, ZkProverCtx,
    ZkVerifierCtx,
};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;
type EF = <GC as IopCtx>::EF;

const NUM_VARIABLES: u32 = 10;

// ============================================================================
// Prover-side sumcheck
// ============================================================================

/// Runs the prover side of sumcheck, sending messages through the public `ZkProverCtx`.
///
/// Returns a `SumcheckView` that can be used to build verification constraints on the prover.
fn sumcheck_prove<GC: ZkIopCtx, MK: ZkMerkleizer<GC>>(
    poly: impl SumcheckPolyFirstRound<GC::EF>,
    ctx: &mut ZkProverCtx<GC, MK>,
    claim: GC::EF,
) -> SumcheckView<ZkProverCtx<GC, MK>> {
    let num_variables = poly.num_variables();
    assert!(num_variables >= 1);

    let mut point: Vec<ProverTranscriptElement<GC, MK>> = Vec::new();
    let mut univariate_poly_coeffs = Vec::new();

    // First round
    let mut uni_poly = poly.sum_as_poly_in_last_t_variables(Some(claim), 1);
    univariate_poly_coeffs.push(ctx.send_values(&uni_poly.coefficients));
    let mut alpha = extract_challenge(ctx.sample());
    point.push(Dorroh::Constant(alpha));
    let mut cursor = poly.fix_t_variables(alpha, 1);

    // Remaining rounds
    for _ in 1..num_variables {
        let round_claim = uni_poly.eval_at_point(alpha);
        uni_poly = cursor.sum_as_poly_in_last_variable(Some(round_claim));
        univariate_poly_coeffs.push(ctx.send_values(&uni_poly.coefficients));
        alpha = extract_challenge(ctx.sample());
        point.push(Dorroh::Constant(alpha));
        cursor = cursor.fix_last_variable(alpha);
    }

    // Point was collected outer-to-inner, reverse to match verifier convention
    point.reverse();

    // Send claimed sum and claimed eval
    let claimed_sum = ctx.send_value(claim);
    let eval = uni_poly.eval_at_point(alpha);
    let claimed_eval = ctx.send_value(eval);

    SumcheckView { univariate_poly_coeffs, point, claimed_sum, claimed_eval }
}

/// Extract a concrete field element from a sampled challenge.
fn extract_challenge<F: TwoAdicField>(expr: Dorroh<F, impl std::fmt::Debug>) -> F {
    match expr {
        Dorroh::Constant(f) => f,
        Dorroh::Element(_) => panic!("expected Dorroh::Constant from sample()"),
    }
}

// ============================================================================
// Verifier-side: read + constrain
// ============================================================================

/// Reads sumcheck proof from the transcript and builds constraints.
/// Works with any `ReadingCtx` (verifier or mask counter).
fn read_and_constrain<C: ReadingCtx>(param: &SumcheckParam, ctx: &mut C) {
    let view = param.read(ctx).expect("failed to read sumcheck proof");
    view.build_constraints(ctx).expect("failed to build sumcheck constraints");
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    // Generate random MLE and compute hypercube sum
    let mle = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);
    let mle_ef = {
        let ef_data: Vec<EF> = mle.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
        Mle::new(RowMajorMatrix::new(ef_data, 1).into())
    };
    let claim: EF = mle.guts().as_slice().iter().copied().sum::<<GC as IopCtx>::F>().into();
    eprintln!("Sumcheck claim (sum over hypercube): {:?}", claim);

    let param = SumcheckParam::new(NUM_VARIABLES, 1);

    // Compute mask length using the verifier's read+constrain pattern
    let mask_length =
        compute_mask_length::<GC, _>(|ctx| read_and_constrain(&param, ctx), |(), _ctx| {});
    eprintln!("Mask length: {}", mask_length);

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        let now = std::time::Instant::now();
        let mut ctx: ZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_only_lin_constraints(mask_length, &mut rng);

        // Prover-side sumcheck: send messages, get back a SumcheckView
        let view = sumcheck_prove::<GC, MK>(mle_ef, &mut ctx, claim);

        // Build constraints on prover context (ConstraintCtx only, no reading)
        view.build_constraints(&mut ctx).expect("failed to build sumcheck constraints");

        let proof = ctx.prove_without_pcs(&mut rng);
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let now = std::time::Instant::now();
        let mut ctx = ZkVerifierCtx::new(proof.open());

        // Verifier reads from transcript and builds constraints
        read_and_constrain(&param, &mut ctx);

        ctx.into_inner().verify_without_pcs().expect("verification failed");
        eprintln!("Verifier time: {:?}", now.elapsed());
    }

    eprintln!("\n=== PASSED ===");
}
