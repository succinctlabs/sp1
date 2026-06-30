use rand::distributions::{Distribution, Standard};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_commit::{Message, Rounds};
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{LinearOracleEval, Mle, Point};
use slop_stacked::stack_multilinear;
use std::sync::Arc;

use crate::compiler::{MleEvalClaim, ReadingCtx, SendingCtx};
use crate::protocols::ProtocolError;
use crate::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

use super::{
    initialize_zk_prover_and_verifier, stacked_oracle_eval, stacked_reduced_point,
    StackedPcsZkProverCtx,
};

type GC = KoalaBearDegree4Duplex;
type EF = <GC as IopCtx>::EF;
type F = <GC as IopCtx>::F;
type MK = Poseidon2KoalaBear16Prover;

/// Prover-only pass: commit the MLE and send its evaluation at the (fixed) opening point.
/// Constraints are emitted later by [`pcs_verify`], which the prover replays.
fn pcs_prove<C, RNG>(ctx: &mut C, mle: Mle<F>, eval_point: &Point<EF>, rng: &mut RNG)
where
    C: SendingCtx<Field = F, Extension = EF>,
    RNG: rand::CryptoRng + rand::Rng,
    Standard: Distribution<F>,
{
    let enc = ctx.num_encoding_variables();
    let eval = mle.eval_at(eval_point).evaluations().as_slice()[0];
    ctx.commit_mle(stack_multilinear(mle, enc), rng).expect("Failed to commit MLEs");
    ctx.send_value(eval);
}

/// Unified read+constrain pass: read the oracle and the claimed eval, then register the opening
/// at the (fixed) `eval_point`. Runs on the verifier and (via replay) on the prover, and is also
/// used by the mask counter.
fn pcs_verify<C: ReadingCtx<Challenge = EF>>(
    ctx: &mut C,
    num_variables: u32,
    eval_point: &Point<EF>,
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracle = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let claimed_eval = ctx.read_one()?;
    ctx.assert_mle_eval(oracle, eval_point, claimed_eval).map_err(ProtocolError::Assert)
}

/// Like [`pcs_verify`], but exercises the custom-oracle path by explicitly reconstructing the
/// *default* stacked decomposition (the eq-coefficient combiner and its matching reduced point).
/// Since it reproduces the default exactly, the resulting proof must verify — a parity check that
/// the custom-oracle plumbing is correct end to end.
fn pcs_verify_with_oracle<C: ReadingCtx<Challenge = EF>>(
    ctx: &mut C,
    num_variables: u32,
    log_num_polynomials: usize,
    eval_point: &Point<EF>,
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracle = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let claimed_eval = ctx.read_one()?;
    let log_stacking_height = eval_point.dimension() - log_num_polynomials;
    let reduced_point = stacked_reduced_point(eval_point, log_stacking_height);
    let oracle_eval = stacked_oracle_eval::<EF>(eval_point, log_stacking_height);
    ctx.assert_mle_eval_with_oracle(&[oracle], &reduced_point, claimed_eval, oracle_eval)
        .map_err(ProtocolError::Assert)
}

/// Prover-only pass for a cross-commitment claim: commit two MLEs and send the single virtual-oracle
/// value `mle0(p0) + mle1(p1)`.
fn cross_prove<C, RNG>(
    ctx: &mut C,
    mle0: &Mle<F>,
    mle1: &Mle<F>,
    p0: &Point<EF>,
    p1: &Point<EF>,
    rng: &mut RNG,
) where
    C: SendingCtx<Field = F, Extension = EF>,
    RNG: rand::CryptoRng + rand::Rng,
    Standard: Distribution<F>,
{
    let enc = ctx.num_encoding_variables();
    ctx.commit_mle(stack_multilinear(mle0.clone(), enc), rng).expect("Failed to commit MLE 0");
    ctx.commit_mle(stack_multilinear(mle1.clone(), enc), rng).expect("Failed to commit MLE 1");
    let e0 = mle0.eval_at(p0).evaluations().as_slice()[0];
    let e1 = mle1.eval_at(p1).evaluations().as_slice()[0];
    ctx.send_value(e0 + e1);
}

/// Unified read+constrain pass for a *cross-commitment* claim: a single virtual oracle whose value
/// is `mle0(p0) + mle1(p1)`, where the two full points share their reduced (column-opening)
/// coordinates but select different stacked columns. The combiner is one [`LinearOracleEval`] whose
/// coefficients are the two points' stacked eq-coefficients concatenated, applied across both
/// commitments' columns.
fn cross_verify<C: ReadingCtx<Challenge = EF>>(
    ctx: &mut C,
    num_variables: u32,
    log_num_polynomials: usize,
    p0: &Point<EF>,
    p1: &Point<EF>,
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracle0 = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let oracle1 = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let claimed_eval = ctx.read_one()?;

    // Both commitments are opened at the shared reduced point (p0 and p1 agree on their last
    // `log_stacking_height` coords).
    let log_stacking_height = p0.dimension() - log_num_polynomials;
    let reduced_point = stacked_reduced_point(p0, log_stacking_height);

    // The cross-commitment combiner reads commitment 0's columns then commitment 1's columns (one
    // round each), so its coefficients are `eq(batch_point0)` followed by `eq(batch_point1)`. This
    // makes `combiner(columns) == mle0(p0) + mle1(p1)`.
    let mut coeffs = stacked_oracle_eval::<EF>(p0, log_stacking_height).coeffs;
    coeffs.extend(stacked_oracle_eval::<EF>(p1, log_stacking_height).coeffs);
    let oracle_eval = LinearOracleEval { coeffs };

    // One cross-commitment claim reading two rounds, both opened at the shared `reduced_point`.
    ctx.assert_mle_multi_eval_with_oracle(
        vec![MleEvalClaim {
            commits: Rounds { rounds: vec![oracle0, oracle1] },
            claimed_eval,
            oracle_eval,
        }],
        &reduced_point,
    )
    .map_err(ProtocolError::Assert)
}

/// Runs the full ZK stacked PCS commit → open → prove/verify workflow for a single claim.
fn run_zk_stacked_pcs_test(num_encoding_variables: u32, log_num_polynomials: u32, verbose: bool) {
    let mut rng = ChaCha20Rng::from_entropy();

    let num_variables = log_num_polynomials + num_encoding_variables;

    if verbose {
        eprintln!("Test configuration:");
        eprintln!("  Total variables: {}", num_variables);
        eprintln!("  Log num polynomials: {}", log_num_polynomials);
        eprintln!("  Variables per column: {}", num_encoding_variables);
    }

    let original_mle = Mle::<F>::rand(&mut rng, 1, num_variables);
    let eval_point = Point::<EF>::rand(&mut rng, num_variables);

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, num_encoding_variables);

    let mask_length = compute_mask_length::<GC, _>(num_encoding_variables, |ctx| {
        pcs_verify(ctx, num_variables, &eval_point)
    });

    // Prover Side
    let prover_start = std::time::Instant::now();
    let zkproof = {
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");

        pcs_prove(&mut pctx, original_mle, &eval_point, &mut rng);
        pcs_verify(&mut pctx, num_variables, &eval_point).expect("zk eager opening failed");

        pctx.prove(&mut rng).expect("zk prove failed")
    };
    if verbose {
        eprintln!("Prover time: {:?}", prover_start.elapsed());
    }

    // Verifier Side
    let verifier_start = std::time::Instant::now();
    {
        let mut vctx = ZkVerifierCtx::init(zkproof, Some(zk_pcs_verifier));
        pcs_verify(&mut vctx, num_variables, &eval_point).expect("zk eager verification failed");
        vctx.verify().expect("Failed to verify proof");
    }
    if verbose {
        eprintln!("Verifier time: {:?}", verifier_start.elapsed());
    }
}

/// Splits a flat MLE into `num_components` pre-stacked block-column components (each a contiguous
/// block range), as a multi-component producer (e.g. jagged's `LongMle`) would hand to the commit.
/// Their columns concatenate, in order, into the full block-column set.
fn split_into_components(
    flat: &Mle<F>,
    num_encoding_variables: u32,
    num_components: usize,
) -> Message<Mle<F>> {
    let data = flat.guts().as_slice();
    assert_eq!(data.len() % num_components, 0);
    let per = data.len() / num_components;
    let mut components: Vec<Arc<Mle<F>>> = Vec::with_capacity(num_components);
    for k in 0..num_components {
        let sub = Mle::from(data[k * per..(k + 1) * per].to_vec());
        components.extend(stack_multilinear(sub, num_encoding_variables));
    }
    Message::from(components)
}

/// Read+constrain pass for two commitments of **different** column counts, batched into one base
/// proof. Their eval points share their last `num_encoding_variables` (reduced) coords but differ in
/// the (variable-length) column-index prefix, so each claim carries its own stacked combiner.
fn variable_columns_verify<C: ReadingCtx<Challenge = EF>>(
    ctx: &mut C,
    num_encoding_variables: u32,
    p0: &Point<EF>,
    p1: &Point<EF>,
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracle0 = ctx.read_oracle(p0.dimension() as u32).ok_or(ProtocolError::MissingOracle)?;
    let oracle1 = ctx.read_oracle(p1.dimension() as u32).ok_or(ProtocolError::MissingOracle)?;
    let claimed0 = ctx.read_one()?;
    let claimed1 = ctx.read_one()?;
    let enc = num_encoding_variables as usize;
    // Both points share the reduced (encoding) coords; the base PCS opens both there.
    let reduced_point = stacked_reduced_point(p0, enc);
    let claims = vec![
        MleEvalClaim {
            commits: Rounds { rounds: vec![oracle0] },
            claimed_eval: claimed0,
            oracle_eval: stacked_oracle_eval::<EF>(p0, enc),
        },
        MleEvalClaim {
            commits: Rounds { rounds: vec![oracle1] },
            claimed_eval: claimed1,
            oracle_eval: stacked_oracle_eval::<EF>(p1, enc),
        },
    ];
    ctx.assert_mle_multi_eval_with_oracle(claims, &reduced_point).map_err(ProtocolError::Assert)
}

/// Two commitments with different `log_num_polys` (column counts), opened at points that share their
/// reduced coords, batched into a single base proof.
#[test]
fn test_zk_stacked_pcs_variable_columns() {
    let mut rng = ChaCha20Rng::from_entropy();
    let num_encoding_variables = 12u32;
    let (log_np0, log_np1) = (4u32, 6u32);
    let nv0 = num_encoding_variables + log_np0;
    let nv1 = num_encoding_variables + log_np1;

    let mle0 = Mle::<F>::rand(&mut rng, 1, nv0);
    let mle1 = Mle::<F>::rand(&mut rng, 1, nv1);
    // p0, p1 share their last `num_encoding_variables` coords (the reduced point) and differ in their
    // variable-length column-index prefix.
    let reduced = Point::<EF>::rand(&mut rng, num_encoding_variables);
    let mut p0 = Point::<EF>::rand(&mut rng, log_np0);
    p0.extend(&reduced);
    let mut p1 = Point::<EF>::rand(&mut rng, log_np1);
    p1.extend(&reduced);
    let e0 = mle0.eval_at(&p0).evaluations().as_slice()[0];
    let e1 = mle1.eval_at(&p1).evaluations().as_slice()[0];

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(2, num_encoding_variables);

    let mask_length = compute_mask_length::<GC, _>(num_encoding_variables, |ctx| {
        variable_columns_verify(ctx, num_encoding_variables, &p0, &p1)
    });

    let zkproof = {
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");
        pctx.commit_mle(stack_multilinear(mle0.clone(), num_encoding_variables), &mut rng)
            .expect("commit 0 failed");
        pctx.commit_mle(stack_multilinear(mle1.clone(), num_encoding_variables), &mut rng)
            .expect("commit 1 failed");
        pctx.send_value(e0);
        pctx.send_value(e1);
        variable_columns_verify(&mut pctx, num_encoding_variables, &p0, &p1)
            .expect("zk eager opening failed");
        pctx.prove(&mut rng).expect("zk prove failed")
    };

    let mut vctx = ZkVerifierCtx::init(zkproof, Some(zk_pcs_verifier));
    variable_columns_verify(&mut vctx, num_encoding_variables, &p0, &p1)
        .expect("zk eager verification failed");
    vctx.verify().expect("Failed to verify proof");
}

/// A single commitment whose data is split into multiple pre-stacked components (one shared mask,
/// many data tensors) must open and verify identically to the single-component case.
#[test]
fn test_zk_stacked_pcs_multi_component() {
    let mut rng = ChaCha20Rng::from_entropy();
    let num_encoding_variables = 12u32;
    let log_num_polynomials = 6u32;
    let num_variables = num_encoding_variables + log_num_polynomials;

    let original_mle = Mle::<F>::rand(&mut rng, 1, num_variables);
    let eval_point = Point::<EF>::rand(&mut rng, num_variables);

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, num_encoding_variables);

    let mask_length = compute_mask_length::<GC, _>(num_encoding_variables, |ctx| {
        pcs_verify(ctx, num_variables, &eval_point)
    });

    let eval = original_mle.eval_at(&eval_point).evaluations().as_slice()[0];
    let zkproof = {
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");
        // Commit the oracle as 4 separate data components under one commitment.
        let components = split_into_components(&original_mle, num_encoding_variables, 4);
        pctx.commit_mle(components, &mut rng).expect("multi-component commit failed");
        pctx.send_value(eval);
        pcs_verify(&mut pctx, num_variables, &eval_point).expect("zk eager opening failed");
        pctx.prove(&mut rng).expect("zk prove failed")
    };

    let mut vctx = ZkVerifierCtx::init(zkproof, Some(zk_pcs_verifier));
    pcs_verify(&mut vctx, num_variables, &eval_point).expect("zk eager verification failed");
    vctx.verify().expect("Failed to verify proof");
}

/// Runs the full workflow registering the claim through the custom-oracle path.
fn run_zk_stacked_pcs_with_oracle_test(num_encoding_variables: u32, log_num_polynomials: u32) {
    let mut rng = ChaCha20Rng::from_entropy();
    let num_variables = log_num_polynomials + num_encoding_variables;
    let log_np = log_num_polynomials as usize;

    let original_mle = Mle::<F>::rand(&mut rng, 1, num_variables);
    let eval_point = Point::<EF>::rand(&mut rng, num_variables);

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, num_encoding_variables);

    let mask_length = compute_mask_length::<GC, _>(num_encoding_variables, |ctx| {
        pcs_verify_with_oracle(ctx, num_variables, log_np, &eval_point)
    });

    let zkproof = {
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");

        pcs_prove(&mut pctx, original_mle, &eval_point, &mut rng);
        pcs_verify_with_oracle(&mut pctx, num_variables, log_np, &eval_point)
            .expect("zk eager opening failed");

        pctx.prove(&mut rng).expect("zk prove failed")
    };

    {
        let mut vctx = ZkVerifierCtx::init(zkproof, Some(zk_pcs_verifier));
        pcs_verify_with_oracle(&mut vctx, num_variables, log_np, &eval_point)
            .expect("zk eager verification failed");
        vctx.verify().expect("Failed to verify proof");
    }
}

#[test]
fn test_zk_stacked_pcs_custom_oracle_parity() {
    // The custom-oracle path reconstructing the stacked default must verify just like the default.
    run_zk_stacked_pcs_with_oracle_test(12, 6);
    run_zk_stacked_pcs_with_oracle_test(14, 8);
}

#[test]
fn test_zk_stacked_pcs_cross_commitment() {
    // A single virtual oracle that depends on TWO commitments, opened together in one base proof at
    // a shared reduced point. The two full points agree on their reduced (column-opening)
    // coordinates but select different stacked columns, and the combiner reads across both
    // commitments' columns to recover `mle0(p0) + mle1(p1)`.
    let mut rng = ChaCha20Rng::from_entropy();
    let num_encoding_variables = 12u32;
    let log_num_polynomials = 6u32;
    let num_variables = num_encoding_variables + log_num_polynomials;
    let log_np = log_num_polynomials as usize;

    let mle0 = Mle::<F>::rand(&mut rng, 1, num_variables);
    let mle1 = Mle::<F>::rand(&mut rng, 1, num_variables);
    // Block convention: the shared reduced (column-opening) coords are the LAST
    // `num_encoding_variables`; the differing column-selector coords are the FIRST
    // `log_num_polynomials`.
    let reduced = Point::<EF>::rand(&mut rng, num_encoding_variables);
    let mut p0 = Point::<EF>::rand(&mut rng, log_num_polynomials);
    p0.extend(&reduced);
    let mut p1 = Point::<EF>::rand(&mut rng, log_num_polynomials);
    p1.extend(&reduced);

    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(2, num_encoding_variables);

    let mask_length = compute_mask_length::<GC, _>(num_encoding_variables, |ctx| {
        cross_verify(ctx, num_variables, log_np, &p0, &p1)
    });

    let zkproof = {
        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");

        cross_prove(&mut pctx, &mle0, &mle1, &p0, &p1, &mut rng);
        cross_verify(&mut pctx, num_variables, log_np, &p0, &p1).expect("zk eager opening failed");

        pctx.prove(&mut rng).expect("zk prove failed")
    };

    {
        let mut vctx = ZkVerifierCtx::init(zkproof, Some(zk_pcs_verifier));
        cross_verify(&mut vctx, num_variables, log_np, &p0, &p1)
            .expect("zk eager verification failed");
        vctx.verify().expect("Failed to verify proof");
    }
}

#[test]
fn test_zk_stacked_pcs_commit_and_prove() {
    eprintln!("\n=== ZK Stacked PCS Commit and Prove Test ===");
    run_zk_stacked_pcs_test(14, 8, true);
    eprintln!("\n=== TEST PASSED ===");
}

#[test]
fn test_zk_stacked_pcs_small_mle() {
    eprintln!("Testing with small MLE");
    run_zk_stacked_pcs_test(12, 6, true);
    eprintln!("Small MLE test PASSED");
}

#[test]
fn test_zk_stacked_pcs_large_mle() {
    eprintln!("Testing with large MLE");
    run_zk_stacked_pcs_test(16, 8, true);
    eprintln!("Large MLE test PASSED");
}
