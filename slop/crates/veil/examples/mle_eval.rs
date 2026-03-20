//! Example: ZK sumcheck using the public VEIL interface.
//!
//! Demonstrates the full prove/verify flow:
//! 1. Generate a random MLE and compute its hypercube sum
//! 2. Prover sends sumcheck messages via `SendingCtx`
//! 3. Verifier reads and checks via `ReadingCtx` + compiler `SumcheckParam`

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, Point};
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::zk::stacked_pcs::{initialize_zk_prover_and_verifier, StackedPcsZkProverCtx};
use slop_veil::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;

const LOG_NUM_POLYNOMIALS: u32 = 8;
const LOG_ENCODING_VARS: u32 = 8;
const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + LOG_ENCODING_VARS;

fn read<C: ReadingCtx>(ctx: &mut C) -> (C::MleOracle, Point<C::Challenge>, C::Expr) {
    let p_oracle = ctx.read_oracle(LOG_ENCODING_VARS, LOG_NUM_POLYNOMIALS).unwrap();
    let point = ctx.sample_point(NUM_VARIABLES);
    let eval = ctx.read_one().unwrap();
    (p_oracle, point, eval)
}

fn build_constraints<C: ConstraintCtx>(
    ctx: &mut C,
    p_oracle: C::MleOracle,
    point: Point<C::Challenge>,
    eval: C::Expr,
) {
    ctx.assert_mle_eval(p_oracle, point, eval);
}

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    // Generate a random MLE
    let p = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);

    let mask_length = compute_mask_length::<GC, _>(read, |(p_o, point, eval), ctx| {
        build_constraints(ctx, p_o, point, eval)
    });
    eprintln!("Mask length: {}", mask_length);

    let (pcs_prover, verifier) = initialize_zk_prover_and_verifier(1, LOG_ENCODING_VARS);

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        eprintln!("Proving...");
        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, pcs_prover, &mut rng);

        // Commit to p
        let commit =
            ctx.commit_mle(p.clone(), LOG_NUM_POLYNOMIALS, &mut rng).expect("failed to commit");
        // Get a random point
        let point = ctx.sample_point(NUM_VARIABLES);

        let eval = p.eval_at(&point)[0];
        let eval = ctx.send_value(eval);

        ctx.assert_mle_eval(commit, point, eval);

        let proof = ctx.prove(&mut rng);
        eprintln!("Proving complete");
        proof
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let mut ctx = ZkVerifierCtx::init(proof, Some(verifier));
        // Verifier reads from transcript and builds constraints
        let (p_oracle, point, eval) = read(&mut ctx);
        build_constraints(&mut ctx, p_oracle, point, eval);
        ctx.verify().expect("verification failed");
    }

    eprintln!("\n=== PASSED ===");
}
