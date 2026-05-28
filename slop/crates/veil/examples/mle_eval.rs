//! Example: random-opening "protocol" for a committed MLE, run against two backends.
//!
//! This is the degenerate terminal case of a veil protocol: nothing is really being
//! reduced — we just commit an MLE, sample a random point, open at that point, and
//! discharge the resulting evaluation claim via `ctx.assert_mle_eval`. Effectively a
//! PCS smoke test.
//!
//! Two functions encode the protocol:
//!
//! - `mle_eval_prove`: prover-only — commit + sample + send.
//! - `mle_eval_verify`: reads the oracle, samples the point, reads the claimed eval,
//!   and registers the PCS opening claim — all in one `ReadingCtx`-generic pass.
//!   Runs unchanged on the verifier and (via the prover's replay `ReadingCtx`) on
//!   the prover.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::Mle;
use slop_veil::compiler::{ReadingCtx, SendingCtx};
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

/// Prover-only entry point: commit `mle`, sample the opening point, compute the
/// evaluation, and send it on the transcript. Constraints are emitted later by
/// `mle_eval_verify`, which the prover replays.
fn mle_eval_prove<C, RNG>(ctx: &mut C, mle: Mle<C::Field>, rng: &mut RNG)
where
    C: SendingCtx,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    ctx.commit_mle(mle.clone(), rng).expect("failed to commit mle");
    let point = ctx.sample_point(NUM_VARIABLES);
    let eval = mle.eval_at(&point).evaluations().as_slice()[0];
    ctx.send_value(eval.into());
}

/// Unified read+constrain pass. Reads the oracle, samples the opening point, reads
/// the claimed eval, and registers the PCS opening claim. Runs on the verifier and
/// (via the prover's replay `ReadingCtx`) on the prover.
fn mle_eval_verify<C: ReadingCtx>(ctx: &mut C) {
    let oracle = ctx.read_oracle(NUM_VARIABLES).unwrap();
    let point = ctx.sample_point(NUM_VARIABLES);
    let claimed_eval = ctx.read_one().unwrap();
    ctx.assert_mle_eval(oracle, point, claimed_eval);
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
        let mask_length = compute_mask_length::<GC>(NUM_ENCODING_VARIABLES, mle_eval_verify);
        eprintln!("Mask length: {mask_length}");

        let mut pctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, zk_pcs_prover, &mut rng)
                .expect("zk init failed");
        mle_eval_prove(&mut pctx, p.clone(), &mut rng);
        mle_eval_verify(&mut pctx);
        let proof = pctx.prove(&mut rng).expect("zk prove failed");

        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = ZkVerifierCtx::init(zk_proof, Some(zk_pcs_verifier));
        mle_eval_verify(&mut vctx);
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
        mle_eval_prove(&mut pctx, p.clone(), &mut rng);
        mle_eval_verify(&mut pctx);
        let proof = pctx.prove(&mut rng).expect("transparent prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(transparent_proof, Some(stacked_verifier));
        mle_eval_verify(&mut vctx);
        vctx.verify().expect("transparent verification failed");
    }
    eprintln!("Transparent backend: PASSED");

    eprintln!("\n=== ALL PASSED ===");
}
