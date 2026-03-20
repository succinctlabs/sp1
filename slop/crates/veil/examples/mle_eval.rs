//! Example: ZK sumcheck using the public VEIL interface.
//!
//! Demonstrates the full prove/verify flow:
//! 1. Generate a random MLE and compute its hypercube sum
//! 2. Prover sends sumcheck messages via `SendingCtx`
//! 3. Verifier reads and checks via `ReadingCtx` + compiler `SumcheckParam`

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::Mle;
use slop_veil::compiler::{ConstraintCtx, ReadingCtx};
use slop_veil::protocols::sumcheck::SumcheckParam;
use slop_veil::zk::stacked_pcs::{StackedPcsProverConfig, StackedPcsZkProverCtx};
use slop_veil::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;
type EF = <GC as IopCtx>::EF;

const NUM_VARIABLES: u32 = 10;

fn read<C: ReadingCtx>(ctx: &mut C) {}

fn build_constraints<C: ConstraintCtx>(ctx: &mut C) {}

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    // Generate a random MLE
    let p = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);

    // let mask_length = compute_mask_length::<GC, _>(
    //     |ctx| param.read(ctx).unwrap(),
    //     |view, ctx| view.build_constraints(ctx).unwrap(),
    // );
    // eprintln!("Mask length: {}", mask_length);

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        let now = std::time::Instant::now();
        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(100, todo!("pcs_prover"), &mut rng);

        // Commit to p

        // Build constraints on prover context (ConstraintCtx only, no reading)
        view.build_constraints(&mut ctx).expect("failed to build sumcheck constraints");

        let proof = ctx.prove(&mut rng);
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let now = std::time::Instant::now();
        let mut ctx = ZkVerifierCtx::init(proof, None);

        // Verifier reads from transcript and builds constraints
        let view = param.read(&mut ctx).expect("failed to read proof");
        view.build_constraints(&mut ctx).expect("failed to build constraints");

        ctx.verify().expect("verification failed");
        eprintln!("Verifier time: {:?}", now.elapsed());
    }

    eprintln!("\n=== PASSED ===");
}
