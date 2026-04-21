//! Example: random-opening "protocol" for a committed MLE.
//!
//! This is the degenerate terminal case of a veil protocol: nothing is really being
//! reduced — we just sample a random point, ask the prover to open the committed
//! oracle at that point, and discharge the resulting MLE-evaluation claim via the
//! primitive `ctx.assert_mle_eval`. Effectively a PCS smoke test.
//!
//! The example follows the standard two-function verifier shape:
//!
//! - `mle_eval_read`: reads the transcript and returns a `MleEvalView`.
//! - `mle_eval_build_constraints`: consumes the view and emits constraints.
//!
//! Both are called directly by the verifier and piped into `compute_mask_length`
//! for mask counting.

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
type F = <GC as IopCtx>::F;
type MK = Poseidon2KoalaBear16Prover;

const LOG_NUM_POLYNOMIALS: u32 = 8;
const NUM_ENCODING_VARIABLES: u32 = 8;
const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + NUM_ENCODING_VARIABLES;

struct MleEvalView<C: ConstraintCtx> {
    oracle: C::MleOracle,
    point: Point<C::Challenge>,
    claimed_eval: C::Expr,
}

fn mle_eval_read<C: ReadingCtx>(ctx: &mut C) -> MleEvalView<C> {
    let oracle = ctx.read_oracle(NUM_ENCODING_VARIABLES, LOG_NUM_POLYNOMIALS).unwrap();
    let point = ctx.sample_point(NUM_VARIABLES);
    let claimed_eval = ctx.read_one().unwrap();
    MleEvalView { oracle, point, claimed_eval }
}

fn mle_eval_build_constraints<C: ConstraintCtx>(view: MleEvalView<C>, ctx: &mut C) {
    ctx.assert_mle_eval(view.oracle, view.point, view.claimed_eval);
}

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    let p = Mle::<F>::rand(&mut rng, 1, NUM_VARIABLES);

    let mask_length = compute_mask_length::<GC, _>(mle_eval_read, mle_eval_build_constraints);
    eprintln!("Mask length: {mask_length}");

    let (pcs_prover, verifier) = initialize_zk_prover_and_verifier(1, NUM_ENCODING_VARIABLES);

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(mask_length, pcs_prover, &mut rng);

        let oracle =
            ctx.commit_mle(p.clone(), LOG_NUM_POLYNOMIALS, &mut rng).expect("failed to commit");
        let point = ctx.sample_point(NUM_VARIABLES);
        let eval = p.eval_at(&point).evaluations().as_slice()[0];
        let claimed_eval = ctx.send_value(eval);

        mle_eval_build_constraints(MleEvalView { oracle, point, claimed_eval }, &mut ctx);

        ctx.prove(&mut rng)
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let mut ctx = ZkVerifierCtx::init(proof, Some(verifier));
        let view = mle_eval_read(&mut ctx);
        mle_eval_build_constraints(view, &mut ctx);
        ctx.verify().expect("verification failed");
    }

    eprintln!("\n=== PASSED ===");
}
