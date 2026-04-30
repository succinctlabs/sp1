//! Transparent-backend facade for the shared integration-test scenarios.
//! Each `#[test]` wires concrete transparent contexts to the generic flows in
//! [`sumcheck_test_primitives`].

mod sumcheck_test_primitives;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_veil::transparent::{
    initialize_transparent_prover_and_verifier, TransparentProverCtx, TransparentVerifierCtx,
};

use crate::sumcheck_test_primitives::{
    generate_random_hadamard_product, generate_random_single_mle,
    sumcheck_batched_single_mles_build_constraints, sumcheck_batched_single_mles_prove,
    sumcheck_batched_single_mles_read, sumcheck_hadamard_build_constraints,
    sumcheck_hadamard_prove, sumcheck_hadamard_read, sumcheck_no_pcs_build_constraints,
    sumcheck_no_pcs_prove, sumcheck_no_pcs_read, sumcheck_single_mle_build_constraints,
    sumcheck_single_mle_prove, sumcheck_single_mle_read,
    sumcheck_triple_hadamard_build_constraints, sumcheck_triple_hadamard_prove,
    sumcheck_triple_hadamard_read,
};

type GC = KoalaBearDegree4Duplex;
type F = <GC as IopCtx>::F;
type EF = <GC as IopCtx>::EF;
type MK = Poseidon2KoalaBear16Prover;

// ============================================================================
// #1: pure sumcheck on Hadamard product, no PCS.
// ============================================================================

#[test]
fn test_sumcheck_no_pcs() {
    let mut rng = ChaCha20Rng::from_entropy();
    const NUM_VARIABLES: u32 = 16;

    let (_, _, product, claim) = generate_random_hadamard_product::<F, EF>(&mut rng, NUM_VARIABLES);

    let proof = {
        let mut pctx: TransparentProverCtx<GC, MK> = TransparentProverCtx::initialize_without_pcs();
        let view = sumcheck_no_pcs_prove(&mut pctx, NUM_VARIABLES, product, claim);
        sumcheck_no_pcs_build_constraints(view, &mut pctx, claim);
        pctx.prove(&mut rng).expect("transparent prove failed")
    };

    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(proof, None);
        let view = sumcheck_no_pcs_read(&mut vctx, NUM_VARIABLES);
        sumcheck_no_pcs_build_constraints(view, &mut vctx, claim);
        vctx.verify().expect("transparent verification failed");
    }
}

// ============================================================================
// #2: single MLE + basic sumcheck + 1 PCS eval.
// ============================================================================

#[test]
fn test_sumcheck_single_mle_with_pcs() {
    let mut rng = ChaCha20Rng::from_entropy();
    const NUM_ENCODING_VARIABLES: u32 = 16;
    const LOG_NUM_POLYNOMIALS: u32 = 8;
    const NUM_VARIABLES: u32 = NUM_ENCODING_VARIABLES + LOG_NUM_POLYNOMIALS;

    let (original_mle, mle_ef, claim) =
        generate_random_single_mle::<F, EF>(&mut rng, NUM_VARIABLES);

    let (stacked_prover, stacked_verifier) = initialize_transparent_prover_and_verifier::<GC, MK>(
        1,
        NUM_ENCODING_VARIABLES,
        LOG_NUM_POLYNOMIALS,
    );

    let proof = {
        let mut pctx: TransparentProverCtx<GC, MK> =
            TransparentProverCtx::initialize(stacked_prover);
        let view = sumcheck_single_mle_prove(
            &mut pctx,
            NUM_ENCODING_VARIABLES,
            LOG_NUM_POLYNOMIALS,
            original_mle,
            mle_ef,
            claim,
            &mut rng,
        );
        sumcheck_single_mle_build_constraints(view, &mut pctx, claim);
        pctx.prove(&mut rng).expect("transparent prove failed")
    };

    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(proof, Some(stacked_verifier));
        let view = sumcheck_single_mle_read(&mut vctx, NUM_ENCODING_VARIABLES, LOG_NUM_POLYNOMIALS);
        sumcheck_single_mle_build_constraints(view, &mut vctx, claim);
        vctx.verify().expect("transparent verification failed");
    }
}

// ============================================================================
// #3: Hadamard sumcheck + 2 PCS evals at the same point (uses `a*b=c`).
// ============================================================================

#[test]
fn test_sumcheck_hadamard_with_pcs() {
    let mut rng = ChaCha20Rng::from_entropy();
    const NUM_ENCODING_VARIABLES: u32 = 16;
    const LOG_NUM_POLYNOMIALS: u32 = 8;
    const NUM_VARIABLES: u32 = NUM_ENCODING_VARIABLES + LOG_NUM_POLYNOMIALS;

    let (mle_base, mle_ext, product, claim) =
        generate_random_hadamard_product::<F, EF>(&mut rng, NUM_VARIABLES);

    // Both oracles are batched into one multi-eval group → one 2-commit PCS proof.
    let (stacked_prover, stacked_verifier) = initialize_transparent_prover_and_verifier::<GC, MK>(
        2,
        NUM_ENCODING_VARIABLES,
        LOG_NUM_POLYNOMIALS,
    );

    let proof = {
        let mut pctx: TransparentProverCtx<GC, MK> =
            TransparentProverCtx::initialize(stacked_prover);
        let view = sumcheck_hadamard_prove(
            &mut pctx,
            NUM_ENCODING_VARIABLES,
            LOG_NUM_POLYNOMIALS,
            mle_base,
            mle_ext,
            product,
            claim,
            &mut rng,
        );
        sumcheck_hadamard_build_constraints(view, &mut pctx, claim);
        pctx.prove(&mut rng).expect("transparent prove failed")
    };

    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(proof, Some(stacked_verifier));
        let view = sumcheck_hadamard_read(&mut vctx, NUM_ENCODING_VARIABLES, LOG_NUM_POLYNOMIALS);
        sumcheck_hadamard_build_constraints(view, &mut vctx, claim);
        vctx.verify().expect("transparent verification failed");
    }
}

// ============================================================================
// #4: RLC-batched N single-MLE sumchecks + N PCS evals at a shared point.
// ============================================================================

#[test]
fn test_sumcheck_batched_single_mles_with_pcs() {
    let mut rng = ChaCha20Rng::from_entropy();
    const NUM_ENCODING_VARIABLES: u32 = 16;
    const LOG_NUM_POLYNOMIALS: u32 = 8;
    const NUM_VARIABLES: u32 = NUM_ENCODING_VARIABLES + LOG_NUM_POLYNOMIALS;
    const NUM_CLAIMS: usize = 3;

    let mut originals = Vec::with_capacity(NUM_CLAIMS);
    let mut mles_ef = Vec::with_capacity(NUM_CLAIMS);
    let mut claims = Vec::with_capacity(NUM_CLAIMS);
    for _ in 0..NUM_CLAIMS {
        let (orig, ef, claim) = generate_random_single_mle::<F, EF>(&mut rng, NUM_VARIABLES);
        originals.push(orig);
        mles_ef.push(ef);
        claims.push(claim);
    }

    // All N MLEs are batched into one multi-eval group → one N-commit PCS proof.
    let (stacked_prover, stacked_verifier) = initialize_transparent_prover_and_verifier::<GC, MK>(
        NUM_CLAIMS,
        NUM_ENCODING_VARIABLES,
        LOG_NUM_POLYNOMIALS,
    );

    let proof = {
        let mut pctx: TransparentProverCtx<GC, MK> =
            TransparentProverCtx::initialize(stacked_prover);
        let view = sumcheck_batched_single_mles_prove(
            &mut pctx,
            NUM_ENCODING_VARIABLES,
            LOG_NUM_POLYNOMIALS,
            originals,
            mles_ef,
            &claims,
            &mut rng,
        );
        sumcheck_batched_single_mles_build_constraints(view, &mut pctx, &claims);
        pctx.prove(&mut rng).expect("transparent prove failed")
    };

    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(proof, Some(stacked_verifier));
        let view = sumcheck_batched_single_mles_read(
            &mut vctx,
            NUM_ENCODING_VARIABLES,
            LOG_NUM_POLYNOMIALS,
            NUM_CLAIMS,
        );
        sumcheck_batched_single_mles_build_constraints(view, &mut vctx, &claims);
        vctx.verify().expect("transparent verification failed");
    }
}

// ============================================================================
// #5: Triple Hadamard, multi-point. ZK panics; transparent handles it.
// ============================================================================

#[test]
fn test_sumcheck_triple_hadamard_multi_point() {
    use slop_multilinear::Mle;

    let mut rng = ChaCha20Rng::from_entropy();
    const NUM_ENCODING_VARIABLES: u32 = 12;
    const LOG_NUM_POLYNOMIALS: u32 = 6;
    const NUM_VARIABLES: u32 = NUM_ENCODING_VARIABLES + LOG_NUM_POLYNOMIALS;

    let mle_f = Mle::<F>::rand(&mut rng, 1, NUM_VARIABLES);
    let mle_g = Mle::<F>::rand(&mut rng, 1, NUM_VARIABLES);
    let mle_h = Mle::<F>::rand(&mut rng, 1, NUM_VARIABLES);

    let build_hadamard = |base: &Mle<F>, ext: &Mle<F>| -> slop_jagged::HadamardProduct<F, EF> {
        use slop_jagged::LongMle;
        use slop_matrix::dense::RowMajorMatrix;
        let long_base = LongMle::from_components(vec![base.clone()], NUM_VARIABLES);
        let ext_ef_data: Vec<EF> = ext.guts().as_slice().iter().map(|&x| x.into()).collect();
        let ext_as_ef = Mle::new(RowMajorMatrix::new(ext_ef_data, 1).into());
        let long_ext = LongMle::from_components(vec![ext_as_ef], NUM_VARIABLES);
        slop_jagged::HadamardProduct { base: long_base, ext: long_ext }
    };
    let compute_claim = |a: &Mle<F>, b: &Mle<F>| -> EF {
        a.guts()
            .as_slice()
            .iter()
            .zip(b.guts().as_slice().iter())
            .map(|(&x, &y)| EF::from(x) * EF::from(y))
            .sum()
    };

    let product_fg = build_hadamard(&mle_f, &mle_g);
    let product_gh = build_hadamard(&mle_g, &mle_h);
    let product_hf = build_hadamard(&mle_h, &mle_f);
    let claim_fg = compute_claim(&mle_f, &mle_g);
    let claim_gh = compute_claim(&mle_g, &mle_h);
    let claim_hf = compute_claim(&mle_h, &mle_f);

    // Same reasoning as #3: six `assert_mle_eval` calls → six 1-commit groups.
    let (stacked_prover, stacked_verifier) = initialize_transparent_prover_and_verifier::<GC, MK>(
        1,
        NUM_ENCODING_VARIABLES,
        LOG_NUM_POLYNOMIALS,
    );

    let proof = {
        let mut pctx: TransparentProverCtx<GC, MK> =
            TransparentProverCtx::initialize(stacked_prover);
        let view = sumcheck_triple_hadamard_prove(
            &mut pctx,
            NUM_ENCODING_VARIABLES,
            LOG_NUM_POLYNOMIALS,
            mle_f,
            mle_g,
            mle_h,
            product_fg,
            product_gh,
            product_hf,
            claim_fg,
            claim_gh,
            claim_hf,
            &mut rng,
        );
        sumcheck_triple_hadamard_build_constraints(view, &mut pctx, claim_fg, claim_gh, claim_hf);
        pctx.prove(&mut rng).expect("transparent prove failed")
    };

    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(proof, Some(stacked_verifier));
        let view =
            sumcheck_triple_hadamard_read(&mut vctx, NUM_ENCODING_VARIABLES, LOG_NUM_POLYNOMIALS);
        sumcheck_triple_hadamard_build_constraints(view, &mut vctx, claim_fg, claim_gh, claim_hf);
        vctx.verify().expect("transparent verification failed");
    }
}
