use std::fs;
use std::time::Duration;

use rand::{rngs::StdRng, SeedableRng};
use serde::Deserialize;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::partially_verify_sumcheck_proof;
use sp1_gpu_cudart::{run_sync_in_place, DevicePoint, TaskScope};
use sp1_gpu_logup_gkr::{
    bench_materialized_sumcheck, extract_outputs, gkr_transition, jagged_first_gkr_layer_to_device,
    prove_round,
};
use sp1_gpu_logup_gkr::{random_first_layer, FirstGkrLayer, GkrCircuitLayer};
use sp1_gpu_utils::config::{Ext, TestGC};

#[derive(Deserialize)]
struct Workload {
    interaction_row_counts: Vec<u32>,
    num_row_variables: u32,
}

fn load_workloads_from_json() -> Vec<Workload> {
    let json_content = fs::read_to_string("crates/logup_gkr/layer_workloads.json")
        .expect("Failed to read crates/logup_gkr/layer_workloads.json");
    serde_json::from_str(&json_content).expect("Failed to parse layer_workloads.json")
}

fn run_benchmark_in_scope(
    t: &TaskScope,
    interaction_row_counts: Vec<u32>,
    num_row_variables: u32,
    name: String,
) -> (Duration, Duration) {
    let mut rng = StdRng::seed_from_u64(1);

    let get_challenger = move || TestGC::default_challenger();

    let layer = random_first_layer(&mut rng, interaction_row_counts, Some(num_row_variables));
    println!("Generated test data for {name}");

    let FirstGkrLayer { jagged_mle, num_interaction_variables, num_row_variables } = layer;

    let first_eval_point = Point::<Ext>::rand(&mut rng, num_interaction_variables + 1);

    let jagged_mle = jagged_first_gkr_layer_to_device(jagged_mle, t);

    let layer = FirstGkrLayer { jagged_mle, num_interaction_variables, num_row_variables };

    let layer = GkrCircuitLayer::FirstLayer(layer);

    t.synchronize_blocking().unwrap();
    let time = std::time::Instant::now();
    let mut layers = vec![layer];
    for _ in 0..num_row_variables - 1 {
        let layer = gkr_transition(layers.last().unwrap());

        layers.push(layer);
    }
    t.synchronize_blocking().unwrap();
    let trace_gen_time = time.elapsed();

    let time = std::time::Instant::now();
    layers.reverse();
    let first_layer = if let GkrCircuitLayer::Materialized(first_layer) = layers.first().unwrap() {
        first_layer
    } else {
        panic!("first layer not correct");
    };
    assert_eq!(first_layer.num_row_variables, 1);

    let output = extract_outputs(first_layer, num_interaction_variables);
    println!("time to extract values: {:?}", time.elapsed());

    // assert_eq!(first_eval_point.dimension(), numerator.num_variables() as usize);
    let first_point_device = DevicePoint::from_host(&first_eval_point, t).unwrap().into_inner();
    let first_point_eq = DevicePoint::new(first_point_device.clone()).partial_lagrange();
    let first_numerator_eval =
        output.numerator.eval_at_eq(&first_point_eq).to_host_vec().unwrap()[0];
    let first_denominator_eval =
        output.denominator.eval_at_eq(&first_point_eq).to_host_vec().unwrap()[0];

    let mut challenger = get_challenger();
    t.synchronize_blocking().unwrap();
    let time = std::time::Instant::now();
    let mut round_proofs = Vec::new();
    // Follow the GKR protocol layer by layer.
    let mut numerator_eval = first_numerator_eval;
    let mut denominator_eval = first_denominator_eval;
    let mut eval_point = first_eval_point.clone();

    for layer in layers {
        let round_proof =
            prove_round(layer, &eval_point, numerator_eval, denominator_eval, &mut challenger);

        // Observe the prover message.
        challenger.observe_ext_element(round_proof.numerator_0);
        challenger.observe_ext_element(round_proof.numerator_1);
        challenger.observe_ext_element(round_proof.denominator_0);
        challenger.observe_ext_element(round_proof.denominator_1);
        // Get the evaluation point for the claims.
        eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
        // Sample the last coordinate.
        let last_coordinate = challenger.sample_ext_element::<Ext>();
        // Compute the evaluation of the numerator and denominator at the last coordinate.
        numerator_eval = round_proof.numerator_0
            + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
        denominator_eval = round_proof.denominator_0
            + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
        eval_point.add_dimension_back(last_coordinate);
        // Add the round proof to the total
        round_proofs.push(round_proof);
    }
    t.synchronize_blocking().unwrap();
    let proof_gen_time = time.elapsed();

    // Follow the GKR protocol layer by layer.
    let mut challenger = get_challenger();
    let mut numerator_eval = first_numerator_eval;
    let mut denominator_eval = first_denominator_eval;
    let mut eval_point = first_eval_point;
    let num_proofs = round_proofs.len();
    println!("Num rounds: {num_proofs}");
    for (i, round_proof) in round_proofs.iter().enumerate() {
        // Get the batching challenge for combining the claims.
        let lambda = challenger.sample_ext_element::<Ext>();
        // Check that the claimed sum is consitent with the previous round values.
        let expected_claim = numerator_eval * lambda + denominator_eval;
        assert_eq!(round_proof.sumcheck_proof.claimed_sum, expected_claim);
        // Verify the sumcheck proof.
        partially_verify_sumcheck_proof(
            &round_proof.sumcheck_proof,
            &mut challenger,
            i + num_interaction_variables as usize + 1,
            3,
        )
        .unwrap();
        // Verify that the evaluation claim is consistent with the prover messages.
        let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
        let eq_eval = Mle::full_lagrange_eval(&point, &eval_point);
        let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
            + round_proof.numerator_1 * round_proof.denominator_0;
        let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
        let expected_final_eval =
            eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);

        assert_eq!(final_eval, expected_final_eval, "Failure in round {i}");

        // Observe the prover message.
        challenger.observe_ext_element(round_proof.numerator_0);
        challenger.observe_ext_element(round_proof.numerator_1);
        challenger.observe_ext_element(round_proof.denominator_0);
        challenger.observe_ext_element(round_proof.denominator_1);

        // Get the evaluation point for the claims.
        eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();

        // Sample the last coordinate and add to the point.
        let last_coordinate = challenger.sample_ext_element::<Ext>();
        eval_point.add_dimension_back(last_coordinate);
        // Update the evaluation of the numerator and denominator at the last coordinate.
        numerator_eval = round_proof.numerator_0
            + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
        denominator_eval = round_proof.denominator_0
            + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
    }
    (trace_gen_time, proof_gen_time)
}

fn print_benchmark_summary(results: &[(Duration, Duration)]) {
    let total_trace_time: Duration = results.iter().map(|(trace, _)| *trace).sum();
    let total_proof_time: Duration = results.iter().map(|(_, proof)| *proof).sum();
    let total_time = total_trace_time + total_proof_time;

    println!("\n=== Final Benchmark Summary ===");
    println!("Total layers benchmarked: {}", results.len());
    println!("Total trace generation time: {total_trace_time:?}");
    println!("Total proof generation time: {total_proof_time:?}");
    println!("Total time: {total_time:?}");
}

const ONLY_SUMCHECK: bool = false;

fn init_tracing() {
    #[cfg(feature = "tokio-blocked")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;
        use tracing_subscriber::Layer;

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let busy_ms =
            std::env::var("TOKIO_BLOCKED_BUSY_MS").map(|s| s.parse().unwrap()).unwrap_or(5000);
        let tokio_blocked_layer = tokio_blocked::TokioBlockedLayer::new()
            .with_warn_busy_single_poll(Some(std::time::Duration::from_micros(busy_ms)));

        tracing_subscriber::registry()
            .with(tokio_blocked_layer)
            .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
            .init();
    }
}

fn main() {
    init_tracing();
    tracing::info!("Starting logup_gkr_bench");

    if ONLY_SUMCHECK {
        let mut rng = StdRng::seed_from_u64(0);
        // let interaction_row_counts: Vec<u32> = vec![4; 66];
        // bench_materialized_sumcheck(interaction_row_counts, &mut rng).await;
        let mut interaction_row_counts: Vec<u32> = vec![
            14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216,
            14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216, 14216, 362856, 362856, 362856,
            362856, 362856, 362856, 362856, 362856, 362856, 362856, 362856, 362856, 362856, 362856,
            362856, 362856, 362856, 312, 312, 312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
            312, 312, 312, 312, 312, 312, 312, 312, 129480, 129480, 129480, 129480, 129480, 129480,
            129480, 129480, 129480, 129480, 129480, 129480, 129480, 129480, 129480, 129480, 129480,
            129480, 129480, 129480, 129480, 129480, 129480, 129480, 129480, 185848, 185848, 185848,
            185848, 185848, 185848, 185848, 185848, 185848, 185848, 185848, 185848, 185848, 185848,
            185848, 185848, 185848, 185848, 185848, 16384, 16384, 16384, 16384, 16384, 16384, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 123640, 123640, 123640, 123640,
            123640, 123640, 123640, 3360, 3360, 3360, 3360, 3360, 3360, 3360, 3360, 3360, 3360,
            3360, 3360, 3360, 3360, 3360, 3360, 3360, 35400, 35400, 35400, 35400, 35400, 35400,
            35400, 35400, 35400, 35400, 35400, 35400, 35400, 35400, 35400, 35400, 35400, 35400,
            35400, 35400, 35400, 162272, 162272, 162272, 162272, 162272, 162272, 162272, 162272,
            162272, 162272, 162272, 162272, 162272, 162272, 162272, 162272, 162272, 162272, 162272,
            162272, 162272, 162272, 162272, 172136, 172136, 172136, 172136, 172136, 172136, 172136,
            172136, 172136, 172136, 172136, 172136, 172136, 172136, 172136, 172136, 172136, 172136,
            172136, 172136, 172136, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
            200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 2472, 2472, 2472, 2472, 2472, 2472,
            2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472, 2472,
            2472, 2472, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384,
            2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 2384, 4568, 4568, 4568, 4568, 4568,
            4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568,
            4568, 16, 16, 16, 16, 16, 16, 16, 61824, 61824, 61824, 61824, 61824, 61824, 61824,
            61824, 61824, 61824, 61824, 61824, 61824, 61824, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            118008, 32768, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304,
            44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304, 44304,
            44304, 44304, 44304, 44304, 44304, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928,
            6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928, 6928,
            6928, 6928, 6928, 6928, 6928, 6928, 6928, 8, 8, 8, 8, 8, 8, 8, 8, 117224, 117224,
            117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224,
            117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224, 117224, 181136,
            181136, 181136, 181136, 181136, 181136, 181136, 181136, 181136, 181136, 181136, 181136,
            181136, 181136, 181136, 181136, 181136, 181136, 181136, 181136, 181136, 3032, 3032,
            3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032, 3032,
            3032, 3032, 3032, 3032, 3032, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640,
            2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 2640, 4648, 4648,
            4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648, 4648,
            4648, 4648, 4648, 4648, 4648, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
            8, 8, 8, 8, 8, 8, 29160, 29160, 29160, 29160, 29160, 29160, 29160, 29160, 29160, 29160,
            29160, 29160, 29160,
        ];
        for _ in 0..9 {
            bench_materialized_sumcheck::<TestGC>(interaction_row_counts.clone(), &mut rng, None);
            interaction_row_counts.iter_mut().for_each(|x| {
                *x /= 2;
                if *x <= 2 {
                    *x = 4;
                }
                if *x % 2 != 0 {
                    *x += 1;
                }
            });
            println!("interaction_row_counts: {interaction_row_counts:?}");
            println!("-----------------------------------------------------------")
        }

        return;
    }
    run_sync_in_place(|t| {
        println!("Loading workloads from JSON...");
        let workloads = load_workloads_from_json();
        println!("Loaded {} workloads", workloads.len());

        // Run warmup with small dataset
        println!("\n=== Running Warmup ===");
        run_benchmark_in_scope(&t, vec![8u32; 3], 10, "Warmup".to_string());

        // Run benchmarks for all real workloads
        println!("\n=== Running Real Workload Benchmarks ===");
        let mut results = Vec::new();

        let len = workloads.len();

        for (i, workload) in workloads.into_iter().enumerate() {
            let layer_name = format!("Layer {i}");
            if workload.interaction_row_counts.iter().any(|&x| x & 1 != 0) {
                panic!("layer {i} has odd interaction col counts");
            }
            let (trace_time, proof_time) = run_benchmark_in_scope(
                &t,
                workload.interaction_row_counts,
                workload.num_row_variables,
                layer_name,
            );
            results.push((trace_time, proof_time));

            // Print progress every 10 layers
            if (i + 1) % 10 == 0 {
                println!("\n--- Completed {} / {} layers ---", i + 1, len);
            }
        }

        print_benchmark_summary(&results);
    })
    .unwrap();
}
