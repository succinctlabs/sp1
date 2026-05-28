//! ZK-backend facade for the shared integration-test scenarios. Each
//! `#[test]` wires concrete ZK contexts to the generic flows in
//! [`sumcheck_test_primitives`].

mod sumcheck_test_primitives;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_veil::zk::stacked_pcs::{initialize_zk_prover_and_verifier, StackedPcsZkProverCtx};
use slop_veil::zk::{compute_mask_length, NoPcsConfig, ZkProverCtx, ZkVerifierCtx};

use crate::sumcheck_test_primitives::{
    generate_random_hadamard_product, generate_random_single_mle,
    sumcheck_batched_single_mles_prove, sumcheck_batched_single_mles_verify,
    sumcheck_hadamard_prove, sumcheck_hadamard_verify, sumcheck_no_pcs_prove,
    sumcheck_no_pcs_verify, sumcheck_single_mle_prove, sumcheck_single_mle_verify,
    sumcheck_triple_hadamard_prove, sumcheck_triple_hadamard_verify,
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
        // No MLE commitments in this protocol, so the encoding width is irrelevant.
        let mask_length = compute_mask_length::<GC>(0, |ctx| {
            sumcheck_no_pcs_verify(ctx, NUM_VARIABLES, claim);
        });
        let mut pctx: ZkProverCtx<GC, NoPcsConfig<MK>> =
            ZkProverCtx::initialize_without_pcs_only_lin(mask_length, &mut rng);
        sumcheck_no_pcs_prove(&mut pctx, NUM_VARIABLES, product, claim);
        sumcheck_no_pcs_verify(&mut pctx, NUM_VARIABLES, claim);
        pctx.prove(&mut rng)
    };

    {
        let mut vctx = ZkVerifierCtx::init(proof, None);
        sumcheck_no_pcs_verify(&mut vctx, NUM_VARIABLES, claim);
        vctx.verify().expect("zk verification failed");
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

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, NUM_ENCODING_VARIABLES);

    let proof = {
        let mask_length = compute_mask_length::<GC>(NUM_ENCODING_VARIABLES, |ctx| {
            sumcheck_single_mle_verify(ctx, NUM_VARIABLES, claim);
        });
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng);
        sumcheck_single_mle_prove(&mut pctx, NUM_VARIABLES, original_mle, mle_ef, claim, &mut rng);
        sumcheck_single_mle_verify(&mut pctx, NUM_VARIABLES, claim);
        pctx.prove(&mut rng)
    };

    {
        let mut vctx = ZkVerifierCtx::init(proof, Some(zk_pcs_verifier));
        sumcheck_single_mle_verify(&mut vctx, NUM_VARIABLES, claim);
        vctx.verify().expect("zk verification failed");
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

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(2, NUM_ENCODING_VARIABLES);

    let proof = {
        let mask_length = compute_mask_length::<GC>(NUM_ENCODING_VARIABLES, |ctx| {
            sumcheck_hadamard_verify(ctx, NUM_VARIABLES, claim);
        });
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs(mask_length, zk_pcs_prover, &mut rng);
        sumcheck_hadamard_prove(
            &mut pctx,
            NUM_VARIABLES,
            mle_base,
            mle_ext,
            product,
            claim,
            &mut rng,
        );
        sumcheck_hadamard_verify(&mut pctx, NUM_VARIABLES, claim);
        pctx.prove(&mut rng)
    };

    {
        let mut vctx = ZkVerifierCtx::init(proof, Some(zk_pcs_verifier));
        sumcheck_hadamard_verify(&mut vctx, NUM_VARIABLES, claim);
        vctx.verify().expect("zk verification failed");
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

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(NUM_CLAIMS, NUM_ENCODING_VARIABLES);

    let proof = {
        let mask_length = compute_mask_length::<GC>(NUM_ENCODING_VARIABLES, |ctx| {
            sumcheck_batched_single_mles_verify(ctx, NUM_VARIABLES, &claims);
        });
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng);
        sumcheck_batched_single_mles_prove(
            &mut pctx,
            NUM_VARIABLES,
            originals,
            mles_ef,
            &claims,
            &mut rng,
        );
        sumcheck_batched_single_mles_verify(&mut pctx, NUM_VARIABLES, &claims);
        pctx.prove(&mut rng)
    };

    {
        let mut vctx = ZkVerifierCtx::init(proof, Some(zk_pcs_verifier));
        sumcheck_batched_single_mles_verify(&mut vctx, NUM_VARIABLES, &claims);
        vctx.verify().expect("zk verification failed");
    }
}

// ============================================================================
// #5: Triple Hadamard, multi-point (known ZK limitation — panics).
// ============================================================================

#[test]
#[should_panic(expected = "Multiple eval claims on the same PCS commitment")]
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

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, NUM_ENCODING_VARIABLES);

    let proof = {
        let mask_length = compute_mask_length::<GC>(NUM_ENCODING_VARIABLES, |ctx| {
            sumcheck_triple_hadamard_verify(ctx, NUM_VARIABLES, claim_fg, claim_gh, claim_hf);
        });
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs(mask_length, zk_pcs_prover, &mut rng);
        sumcheck_triple_hadamard_prove(
            &mut pctx,
            NUM_VARIABLES,
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
        sumcheck_triple_hadamard_verify(&mut pctx, NUM_VARIABLES, claim_fg, claim_gh, claim_hf);
        pctx.prove(&mut rng)
    };

    {
        let mut vctx = ZkVerifierCtx::init(proof, Some(zk_pcs_verifier));
        sumcheck_triple_hadamard_verify(&mut vctx, NUM_VARIABLES, claim_fg, claim_gh, claim_hf);
        vctx.verify().expect("zk verification failed");
    }
}
