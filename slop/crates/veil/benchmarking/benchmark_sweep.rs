// #![allow(clippy::disallowed_types)]

// //! Benchmark sweep: compares standard vs ZK sumcheck+PCS overhead across parameter space.
// //!
// //! Iterates over (TOTAL_NUM_VARS, LOG_STACKING_HEIGHT) and writes results to CSV.
// //! Uses median of N iterations (with 1 warm-up) for noise-robust measurements.
// //!
// //! Run: `cargo run --example benchmark_sweep --release -p slop-zk-sumcheck`
// //! For best results: `sudo nice -n -20 cargo run --example benchmark_sweep --release -p slop-zk-sumcheck`
// //! Results are saved to `benchmarking/benchmark_sweep_results.csv`.

// use std::fs::File;
// use std::io::Write;
// use std::time::{Duration, Instant};

// use rand::SeedableRng;
// use rand_chacha::ChaCha20Rng;
// use slop_algebra::AbstractField;
// use slop_basefold::{BasefoldVerifier, FriConfig};
// use slop_basefold_prover::BasefoldProver;
// use slop_challenger::{CanObserve, IopCtx};
// use slop_commit::Rounds;
// use slop_koala_bear::KoalaBearDegree4Duplex;
// use slop_matrix::dense::RowMajorMatrix;
// use slop_merkle_tree::Poseidon2KoalaBear16Prover;
// use slop_multilinear::{Mle, MultilinearPcsProver};
// use slop_stacked::{StackedPcsProver, StackedPcsVerifier};
// use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};
// use slop_veil::example_zk_sumcheck::{
//     verifier::ZkPartialSumcheckParameters, zk_reduce_sumcheck_to_evaluation, ZkPartialSumcheckProof,
// };
// use slop_veil::inner::{
//     compute_mask_length, ConstraintContextInnerExt, MleCommitmentIndex, ZkCnstrAndReadingCtxInner,
//     ZkIopCtx, ZkProtocolParameters, ZkProtocolProof,
// };
// use slop_veil::stacked_pcs::{
//     initialize_zk_prover_and_verifier, prover::StackedPcsZkProverContext,
//     verifier::StackedPcsZkVerificationContext,
// };

// type GC = KoalaBearDegree4Duplex;
// type F = <GC as IopCtx>::F;
// type EF = <GC as IopCtx>::EF;

// fn generate_random_mle(rng: &mut impl rand::Rng, num_vars: u32) -> (Mle<F>, Mle<EF>, EF) {
//     let original_mle = Mle::<F>::rand(rng, 1, num_vars);
//     let ef_data: Vec<EF> = original_mle.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
//     let mle_ef = Mle::new(RowMajorMatrix::new(ef_data, 1).into());
//     let claim: EF = original_mle.guts().as_slice().iter().copied().sum::<F>().into();
//     (original_mle, mle_ef, claim)
// }

// /// Returns the median of a slice of Durations.
// fn median(samples: &mut [Duration]) -> Duration {
//     samples.sort();
//     let n = samples.len();
//     if n % 2 == 1 {
//         samples[n / 2]
//     } else {
//         (samples[n / 2 - 1] + samples[n / 2]) / 2
//     }
// }

// /// Returns the standard deviation in milliseconds.
// fn stddev_ms(samples: &[Duration]) -> f64 {
//     let n = samples.len() as f64;
//     let mean = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / n;
//     let variance =
//         samples.iter().map(|d| (d.as_secs_f64() - mean).powi(2)).sum::<f64>() / (n - 1.0);
//     variance.sqrt() * 1000.0
// }

// /// Run the standard sumcheck + stacked PCS path, return (prover_time, verifier_time).
// fn run_standard(
//     original_mle: &Mle<F>,
//     mle_ef: &Mle<EF>,
//     claim: EF,
//     num_stacked_vars: u32,
//     log_stacking_height: u32,
//     total_num_vars: u32,
// ) -> (Duration, Duration) {
//     let basefold_verifier = BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 1);

//     let (commitment, sumcheck_proof, pcs_proof, prover_time) = {
//         let prover_start = Instant::now();

//         let basefold_prover =
//             BasefoldProver::<GC, Poseidon2KoalaBear16Prover>::new(&basefold_verifier);
//         let batch_size = 1usize << log_stacking_height;
//         let stacked_prover = StackedPcsProver::new(basefold_prover, num_stacked_vars, batch_size);

//         let mle_message = slop_commit::Message::from(vec![original_mle.clone()]);
//         let (commitment, prover_data, _padding) =
//             stacked_prover.commit_multilinears(mle_message).unwrap();

//         let mut prover_challenger = GC::default_challenger();
//         prover_challenger.observe(commitment);

//         let (sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<F, EF, _>(
//             vec![mle_ef.clone()],
//             &mut prover_challenger,
//             vec![claim],
//             1,
//             EF::one(),
//         );

//         let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();
//         let pcs_proof = stacked_prover
//             .prove_trusted_evaluation(
//                 eval_point,
//                 eval_claim,
//                 Rounds { rounds: vec![prover_data] },
//                 &mut prover_challenger,
//             )
//             .unwrap();

//         (commitment, sumcheck_proof, pcs_proof, prover_start.elapsed())
//     };

//     let verifier_time = {
//         let verifier_start = Instant::now();

//         let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, num_stacked_vars);
//         let mut verifier_challenger = GC::default_challenger();
//         verifier_challenger.observe(commitment);

//         partially_verify_sumcheck_proof::<F, EF, _>(
//             &sumcheck_proof,
//             &mut verifier_challenger,
//             total_num_vars as usize,
//             1,
//         )
//         .unwrap();

//         let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();
//         let round_area = (1usize << total_num_vars).next_multiple_of(1usize << num_stacked_vars);
//         stacked_verifier
//             .verify_trusted_evaluation(
//                 &[commitment],
//                 &[round_area],
//                 &eval_point,
//                 &pcs_proof,
//                 eval_claim,
//                 &mut verifier_challenger,
//             )
//             .unwrap();

//         verifier_start.elapsed()
//     };

//     (prover_time, verifier_time)
// }

// /// Run the ZK sumcheck + ZK stacked PCS path, return (prover_time, verifier_time).
// fn run_zk(
//     original_mle: &Mle<F>,
//     mle_ef: &Mle<EF>,
//     claim: EF,
//     num_stacked_vars: u32,
//     log_stacking_height: u32,
//     total_num_vars: u32,
//     rng: &mut ChaCha20Rng,
// ) -> (Duration, Duration) {
//     fn read_all<GC2: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC2>>(
//         context: &mut C,
//         num_stacked_vars: u32,
//         log_stacking_height: u32,
//         total_num_vars: u32,
//     ) -> (MleCommitmentIndex, ZkPartialSumcheckProof<GC2, C>) {
//         let commitment_index = context
//             .read_next_pcs_commitment(num_stacked_vars as usize, log_stacking_height as usize)
//             .unwrap();
//         let claimed_sum_index = context.read_one().unwrap();
//         let sumcheck_data =
//             ZkPartialSumcheckParameters::basic_sumcheck(total_num_vars, claimed_sum_index)
//                 .read_proof_from_transcript(context)
//                 .unwrap();
//         (commitment_index, sumcheck_data)
//     }

//     fn build_all_constraints<GC2: ZkIopCtx, C: ConstraintContextInnerExt<GC2::EF>>(
//         (commitment_index, sumcheck_data): (MleCommitmentIndex, ZkPartialSumcheckProof<GC2, C>),
//         ctx: &mut C,
//     ) {
//         ctx.assert_mle_eval(
//             commitment_index,
//             sumcheck_data.point.clone().into(),
//             sumcheck_data.claimed_eval.clone(),
//         );
//         sumcheck_data.build_constraints();
//     }

//     let (zk_basefold_prover, zk_stacked_verifier) =
//         initialize_zk_prover_and_verifier::<GC>(1, num_stacked_vars);

//     let read_all_closure =
//         |ctx: &mut _| read_all::<GC, _>(ctx, num_stacked_vars, log_stacking_height, total_num_vars);
//     let build_closure = build_all_constraints::<GC, _>;

//     let (zkproof, prover_time) = {
//         let prover_start = Instant::now();

//         let masks_length = compute_mask_length::<GC, _, _, _>(read_all_closure, build_closure);
//         let mut prover_context: StackedPcsZkProverContext<GC> =
//             StackedPcsZkProverContext::initialize_only_lin_constraints(masks_length, rng);

//         let commitment_index = prover_context
//             .commit_mle(
//                 original_mle.clone(),
//                 log_stacking_height as usize,
//                 &zk_basefold_prover,
//                 rng,
//             )
//             .expect("Failed to commit MLE");

//         let sum_claim = prover_context.add_value(claim);
//         let (_, sumcheck_constraint_data) =
//             zk_reduce_sumcheck_to_evaluation(mle_ef.clone(), &mut prover_context, sum_claim);

//         build_all_constraints::<GC, _>(
//             (commitment_index, sumcheck_constraint_data),
//             &mut prover_context,
//         );

//         let zkproof = prover_context.prove(rng, Some(&zk_basefold_prover));

//         (zkproof, prover_start.elapsed())
//     };

//     let verifier_time = {
//         let verifier_start = Instant::now();

//         let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();
//         let (commitment_index, sumcheck_data) =
//             read_all::<GC, _>(&mut context, num_stacked_vars, log_stacking_height, total_num_vars);
//         build_all_constraints::<GC, _>((commitment_index, sumcheck_data), &mut context);
//         context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify");

//         verifier_start.elapsed()
//     };

//     (prover_time, verifier_time)
// }

// fn main() {
//     const NUM_WARMUP: usize = 1;
//     const NUM_MEASURED: usize = 5;
//     const MIN_TOTAL_VARS: u32 = 10;
//     const MAX_TOTAL_VARS: u32 = 25;
//     const MIN_LOG_STACK: u32 = 5;
//     const MAX_LOG_STACK: u32 = 15;

//     let output_path =
//         concat!(env!("CARGO_MANIFEST_DIR"), "/benchmarking/benchmark_sweep_results.csv");
//     let mut file = File::create(output_path).expect("Failed to create output file");

//     writeln!(
//         file,
//         "total_num_vars,log_stacking_height,num_stacked_vars,\
//          std_prover_median_ms,std_prover_stddev_ms,\
//          std_verifier_median_ms,std_verifier_stddev_ms,\
//          zk_prover_median_ms,zk_prover_stddev_ms,\
//          zk_verifier_median_ms,zk_verifier_stddev_ms,\
//          prover_overhead,verifier_overhead"
//     )
//     .unwrap();
//     file.flush().unwrap();

//     eprintln!(
//         "Benchmark sweep: TOTAL_NUM_VARS {}..{}, LOG_STACKING_HEIGHT {}..{}",
//         MIN_TOTAL_VARS, MAX_TOTAL_VARS, MIN_LOG_STACK, MAX_LOG_STACK
//     );
//     eprintln!("Warm-up: {NUM_WARMUP}, Measured iterations: {NUM_MEASURED} (reporting median)");
//     eprintln!("Results will be saved to: {output_path}\n");

//     let mut rng = ChaCha20Rng::from_entropy();

//     for total_num_vars in MIN_TOTAL_VARS..=MAX_TOTAL_VARS {
//         let max_log_stack = MAX_LOG_STACK.min(total_num_vars - 1);
//         for log_stacking_height in MIN_LOG_STACK..=max_log_stack {
//             let num_stacked_vars = total_num_vars - log_stacking_height;

//             // ZK path needs codeword_length = 2^(num_stacked_vars+1) large enough for
//             // 100-bit security in the proximity check. Requires num_stacked_vars >= 10.
//             if num_stacked_vars < 10 {
//                 continue;
//             }

//             eprint!(
//                 "total_vars={total_num_vars}, log_stack={log_stacking_height}, \
//                  stacked_vars={num_stacked_vars} ... "
//             );
//             std::io::Write::flush(&mut std::io::stdout()).unwrap();

//             let (original_mle, mle_ef, claim) = generate_random_mle(&mut rng, total_num_vars);

//             // Warm-up: run but discard results (primes caches, allocator, etc.)
//             for _ in 0..NUM_WARMUP {
//                 let _ = run_standard(
//                     &original_mle,
//                     &mle_ef,
//                     claim,
//                     num_stacked_vars,
//                     log_stacking_height,
//                     total_num_vars,
//                 );
//                 let _ = run_zk(
//                     &original_mle,
//                     &mle_ef,
//                     claim,
//                     num_stacked_vars,
//                     log_stacking_height,
//                     total_num_vars,
//                     &mut rng,
//                 );
//             }

//             // Measured iterations
//             let mut std_prover_samples = Vec::with_capacity(NUM_MEASURED);
//             let mut std_verifier_samples = Vec::with_capacity(NUM_MEASURED);
//             let mut zk_prover_samples = Vec::with_capacity(NUM_MEASURED);
//             let mut zk_verifier_samples = Vec::with_capacity(NUM_MEASURED);

//             for _ in 0..NUM_MEASURED {
//                 let (sp, sv) = run_standard(
//                     &original_mle,
//                     &mle_ef,
//                     claim,
//                     num_stacked_vars,
//                     log_stacking_height,
//                     total_num_vars,
//                 );
//                 std_prover_samples.push(sp);
//                 std_verifier_samples.push(sv);

//                 let (zp, zv) = run_zk(
//                     &original_mle,
//                     &mle_ef,
//                     claim,
//                     num_stacked_vars,
//                     log_stacking_height,
//                     total_num_vars,
//                     &mut rng,
//                 );
//                 zk_prover_samples.push(zp);
//                 zk_verifier_samples.push(zv);
//             }

//             let std_p_sd = stddev_ms(&std_prover_samples);
//             let std_v_sd = stddev_ms(&std_verifier_samples);
//             let zk_p_sd = stddev_ms(&zk_prover_samples);
//             let zk_v_sd = stddev_ms(&zk_verifier_samples);

//             let std_p = median(&mut std_prover_samples).as_secs_f64() * 1000.0;
//             let std_v = median(&mut std_verifier_samples).as_secs_f64() * 1000.0;
//             let zk_p = median(&mut zk_prover_samples).as_secs_f64() * 1000.0;
//             let zk_v = median(&mut zk_verifier_samples).as_secs_f64() * 1000.0;
//             let p_overhead = zk_p / std_p;
//             let v_overhead = zk_v / std_v;

//             writeln!(
//                 file,
//                 "{total_num_vars},{log_stacking_height},{num_stacked_vars},\
//                  {std_p:.3},{std_p_sd:.3},\
//                  {std_v:.3},{std_v_sd:.3},\
//                  {zk_p:.3},{zk_p_sd:.3},\
//                  {zk_v:.3},{zk_v_sd:.3},\
//                  {p_overhead:.4},{v_overhead:.4}"
//             )
//             .unwrap();
//             file.flush().unwrap();

//             eprintln!(
//                 "std_p={std_p:.1}ms(±{std_p_sd:.1}) std_v={std_v:.1}ms(±{std_v_sd:.1}) \
//                  zk_p={zk_p:.1}ms(±{zk_p_sd:.1}) zk_v={zk_v:.1}ms(±{zk_v_sd:.1}) \
//                  p_oh={p_overhead:.2}x v_oh={v_overhead:.2}x"
//             );
//         }
//     }

//     eprintln!("\nDone! Results saved to {output_path}");
// }
fn main() {}
