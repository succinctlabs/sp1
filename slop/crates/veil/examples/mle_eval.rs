//! Example: random-opening "protocol" for a committed MLE, run against two backends.
//!
//! This is the degenerate terminal case of a veil protocol: nothing is really being
//! reduced — we just commit an MLE, sample a random point, open at that point, and
//! discharge the resulting evaluation claim via the primitive `ctx.assert_mle_eval`.
//! Effectively a PCS smoke test.
//!
//! The protocol is written once, generically over `SendingCtx` / `ReadingCtx`, then
//! run first with the zero-knowledge backend (`ZkProverCtx` / `ZkVerifierCtx`) and
//! afterwards with the transparent backend (`TransparentProverCtx` /
//! `TransparentVerifierCtx`).
//!
//! Shape:
//!
//! - `mle_eval_read` / `mle_eval_prove`: mirror entry points — one reads the
//!   transcript on the verifier side, the other commits + samples + sends on the
//!   prover side. Both return an [`MleEvalView`].
//! - `mle_eval_build_constraints`: the shared constraint-building pass used by both
//!   sides.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, Point};
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::transparent::{
    initialize_transparent_prover_and_verifier, TransparentProverCtx, TransparentVerifierCtx,
};
use slop_veil::zk::stacked_pcs::{initialize_zk_prover_and_verifier, StackedPcsZkProverCtx};
use slop_veil::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type F = <GC as IopCtx>::F;
type MK = Poseidon2KoalaBear16Prover;

const LOG_NUM_POLYNOMIALS: u32 = 8;
const NUM_ENCODING_VARIABLES: u32 = 8;
const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + NUM_ENCODING_VARIABLES;

// ============================================================================
// Generic protocol code
// ============================================================================

struct MleEvalView<C: ConstraintCtx> {
    oracle: C::MleOracle,
    point: Point<C::Challenge>,
    claimed_eval: C::Expr,
}

/// Verifier-side entry point: read the committed oracle, sample the opening point,
/// and read the prover's claimed evaluation out of the transcript.
fn mle_eval_read<C: ReadingCtx>(ctx: &mut C) -> MleEvalView<C> {
    let oracle = ctx.read_oracle(NUM_ENCODING_VARIABLES, LOG_NUM_POLYNOMIALS).unwrap();
    let point = ctx.sample_point(NUM_VARIABLES);
    let claimed_eval = ctx.read_one().unwrap();
    MleEvalView { oracle, point, claimed_eval }
}

/// Prover-side entry point: commit `mle`, sample the opening point, compute the
/// evaluation, send it on the transcript, and return the matching [`MleEvalView`]
/// for the caller to feed into [`mle_eval_build_constraints`].
fn mle_eval_prove<C, RNG>(ctx: &mut C, mle: Mle<C::Field>, rng: &mut RNG) -> MleEvalView<C>
where
    C: SendingCtx,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    let oracle =
        ctx.commit_mle(mle.clone(), LOG_NUM_POLYNOMIALS, rng).expect("failed to commit mle");
    let point = ctx.sample_point(NUM_VARIABLES);
    let eval = mle.eval_at(&point).evaluations().as_slice()[0];
    let claimed_eval = ctx.send_value(eval.into());
    MleEvalView { oracle, point, claimed_eval }
}

/// Shared constraint-building pass used by both sides.
fn mle_eval_build_constraints<C: ConstraintCtx>(view: MleEvalView<C>, ctx: &mut C) {
    ctx.assert_mle_eval(view.oracle, view.point, view.claimed_eval);
}

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    let p = Mle::<F>::rand(&mut rng, 1, NUM_VARIABLES);

    // ZK backend.
    eprintln!("\n=== ZK BACKEND ===");
    let (zk_pcs_prover, zk_pcs_verifier) =
        initialize_zk_prover_and_verifier(1, NUM_ENCODING_VARIABLES);

    let zk_proof = {
        let now = std::time::Instant::now();
        let mask_length = compute_mask_length::<GC, _>(mle_eval_read, mle_eval_build_constraints);
        eprintln!("Mask length: {mask_length}");

        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng);
        let view = mle_eval_prove(&mut pctx, p.clone(), &mut rng);
        mle_eval_build_constraints(view, &mut pctx);
        let proof = pctx.prove(&mut rng);

        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = ZkVerifierCtx::init(zk_proof, Some(zk_pcs_verifier));
        let view = mle_eval_read(&mut vctx);
        mle_eval_build_constraints(view, &mut vctx);
        vctx.verify().expect("zk verification failed");
    }
    eprintln!("ZK backend: PASSED");

    // Transparent backend.
    eprintln!("\n=== TRANSPARENT BACKEND ===");
    let (stacked_prover, stacked_verifier) = initialize_transparent_prover_and_verifier::<GC, MK>(
        1,
        NUM_ENCODING_VARIABLES,
        LOG_NUM_POLYNOMIALS,
    );

    let transparent_proof = {
        let now = std::time::Instant::now();
        let mut pctx: TransparentProverCtx<GC, MK> =
            TransparentProverCtx::initialize(stacked_prover);
        let view = mle_eval_prove(&mut pctx, p.clone(), &mut rng);
        mle_eval_build_constraints(view, &mut pctx);
        let proof = pctx.prove(&mut rng).expect("transparent prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(transparent_proof, Some(stacked_verifier));
        let view = mle_eval_read(&mut vctx);
        mle_eval_build_constraints(view, &mut vctx);
        vctx.verify().expect("transparent verification failed");
    }
    eprintln!("Transparent backend: PASSED");

    eprintln!("\n=== ALL PASSED ===");
}
