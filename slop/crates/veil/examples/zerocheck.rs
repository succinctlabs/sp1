// //! Example: ZK sumcheck using the public VEIL interface.
// //!
// //! Demonstrates the full prove/verify flow:
// //! 1. Generate a random MLE and compute its hypercube sum
// //! 2. Prover sends sumcheck messages via `SendingCtx`
// //! 3. Verifier reads and checks via `ReadingCtx` + compiler `SumcheckParam`

// use rand::SeedableRng;
// use rand_chacha::ChaCha20Rng;
// use slop_algebra::AbstractField;
// use slop_challenger::IopCtx;
// use slop_koala_bear::KoalaBearDegree4Duplex;
// use slop_merkle_tree::Poseidon2KoalaBear16Prover;
// use slop_multilinear::Mle;
// use slop_veil::compiler::sumcheck::SumcheckParam;
// use slop_veil::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

// type GC = KoalaBearDegree4Duplex;
// type MK = Poseidon2KoalaBear16Prover;
// type EF = <GC as IopCtx>::EF;

// const NUM_VARIABLES: u32 = 10;

// struct Zerocheck;

// fn main() {
//     let mut rng = ChaCha20Rng::from_entropy();

//     // Generate random MLEs and their product as an MLE
//     let p = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);
//     let q = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);
//     // Allocate an Mle for the product
//     let r = Mle::<<GC as IopCtx>::F>::uninit(1, 1 << NUM_VARIABLES);
//     // Populate it with the product values
//     let r_guts = r.guts_mut().as_mut_slice();
//     r_guts
//         .iter_mut()
//         .zip(p.hypercube_iter())
//         .zip(q.hypercube_iter())
//         .for_each(|((r_val, p_slice), q_slice)| *r_val = p_slice[0] * q_slice[0]);

//     // We want to prove that `r(x) = p(x) * q(x)` on the hypercube.
//     //
//     // We will commit to p, q, r. Then get a random challenge and prove via sumcheck
//     //  0 = \sum_{x} (p(x)q(x) - r(x)) * eq(x, Z)

//     let claim = EF::zero();

//     let param = SumcheckParam::new(NUM_VARIABLES, 3);

//     // Compute mask length using the verifier's read+constrain pattern
//     let mask_length = compute_mask_length::<GC, _>(
//         |ctx| param.read(ctx).unwrap(),
//         |view, ctx| view.build_constraints(ctx).unwrap(),
//     );
//     eprintln!("Mask length: {}", mask_length);

//     // === PROVER ===
//     eprintln!("\n=== PROVER ===");
//     let proof = {
//         let now = std::time::Instant::now();
//         let mut ctx: ZkProverCtx<GC, MK> =
//             ZkProverCtx::initialize_only_lin_constraints(mask_length, &mut rng);

//         // Prover-side sumcheck: send messages, get back a SumcheckView
//         let view = param.prove(mle_ef, &mut ctx, claim);

//         // Build constraints on prover context (ConstraintCtx only, no reading)
//         view.build_constraints(&mut ctx).expect("failed to build sumcheck constraints");

//         let proof = ctx.prove_without_pcs(&mut rng);
//         eprintln!("Prover time: {:?}", now.elapsed());
//         proof
//     };

//     // === VERIFIER ===
//     eprintln!("\n=== VERIFIER ===");
//     {
//         let now = std::time::Instant::now();
//         let mut ctx = ZkVerifierCtx::init(proof, None);

//         // Verifier reads from transcript and builds constraints
//         let view = param.read(&mut ctx).expect("failed to read proof");
//         view.build_constraints(&mut ctx).expect("failed to build constraints");

//         ctx.verify().expect("verification failed");
//         eprintln!("Verifier time: {:?}", now.elapsed());
//     }

//     eprintln!("\n=== PASSED ===");
// }

fn main() {}
