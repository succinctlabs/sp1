//! Each chip may have some associated lookups. We place each chip's traces together in a single "jagged" buffer, since each chip may have a different height.
//! Then, once we have run GKR for every chip to completion, we join the results together with the "interactions layers".
//!
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use slop_algebra::AbstractField;
use slop_alloc::HasBackend;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx, VariableLengthChallenger};
use slop_multilinear::{Mle, MleEval, MultilinearPcsChallenger, Point};
use slop_tensor::Tensor;
use sp1_gpu_basefold::{DeviceGrindingChallenger, GrindingPowCudaProver};
use sp1_gpu_cudart::{DeviceMle, DevicePoint, TaskScope};
use tracing::instrument;

use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    beta_seed_dim_for_scope, global_output_sum,
    prover::Record,
    pv_interaction_max_arity, transition_fold, Chip, ChipEvaluation, LogUpEvaluations,
    LogUpGkrVerifier, LogupGkrProof, LogupGkrRoundProof, ShardContext, GKR_GRINDING_BITS,
};

use crate::execution::{build_interaction_layers, InteractionLayers};
use sp1_gpu_utils::traces::JaggedTraceMle;
use sp1_gpu_utils::{Ext, Felt};
use sp1_gpu_zerocheck::primitives::round_batch_evaluations;
mod execution;
mod interactions;
mod layer;
mod sumcheck;
mod tracegen;
mod utils;

pub use interactions::Interactions;
pub use tracegen::{generate_gkr_circuit, CudaLogUpGkrOptions};
pub use utils::*;

pub use sumcheck::{
    bench_materialized_sumcheck, first_round_sumcheck, materialized_round_sumcheck,
};

pub use execution::{extract_outputs, gkr_transition};

fn prove_materialized_round<C: FieldChallenger<Felt>>(
    layer: GkrLayer,
    eval_point: &Point<Ext>,
    numerator_eval: Ext,
    denominator_eval: Ext,
    challenger: &mut C,
) -> LogupGkrRoundProof<Ext> {
    let lambda = challenger.sample_ext_element::<Ext>();
    let claim = numerator_eval * lambda + denominator_eval;
    let (interaction_point, row_point) =
        eval_point.split_at(layer.num_interaction_variables as usize);

    let backend = layer.jagged_mle.backend().clone();
    let interaction_point =
        DevicePoint::from_host(&interaction_point, &backend).unwrap().into_inner();
    let row_point = DevicePoint::from_host(&row_point, &backend).unwrap().into_inner();
    let eq_interaction = DevicePoint::new(interaction_point).partial_lagrange();
    let eq_row = DevicePoint::new(row_point).partial_lagrange();
    let sumcheck_poly = LogupRoundPolynomial {
        layer: PolynomialLayer::CircuitLayer(layer),
        eq_row,
        eq_interaction,
        lambda,
        eq_adjustment: Ext::one(),
        padding_adjustment: Ext::one(),
        point: eval_point.clone(),
    };

    // Produce the sumcheck proof.
    let (sumcheck_proof, openings) =
        sumcheck::materialized_round_sumcheck(sumcheck_poly, challenger, claim);
    let [numerator_0, numerator_1, denominator_0, denominator_1] = openings.try_into().unwrap();

    LogupGkrRoundProof { numerator_0, numerator_1, denominator_0, denominator_1, sumcheck_proof }
}

fn prove_first_round<C: FieldChallenger<Felt>>(
    layer: FirstGkrLayer,
    eval_point: &Point<Ext>,
    numerator_eval: Ext,
    denominator_eval: Ext,
    challenger: &mut C,
) -> LogupGkrRoundProof<Ext> {
    let lambda = challenger.sample_ext_element::<Ext>();
    let claim = numerator_eval * lambda + denominator_eval;
    let (interaction_point, row_point) =
        eval_point.split_at(layer.num_interaction_variables as usize);

    let backend = layer.jagged_mle.backend();
    let interaction_point =
        DevicePoint::from_host(&interaction_point, backend).unwrap().into_inner();
    let row_point = DevicePoint::from_host(&row_point, backend).unwrap().into_inner();
    let eq_interaction = DevicePoint::new(interaction_point).partial_lagrange();
    let eq_row = DevicePoint::new(row_point).partial_lagrange();

    let sumcheck_poly =
        FirstLayerPolynomial { layer, eq_row, eq_interaction, lambda, point: eval_point.clone() };

    // Produce the sumcheck proof.
    let (sumcheck_proof, openings) =
        sumcheck::first_round_sumcheck(sumcheck_poly, challenger, claim);
    let [numerator_0, numerator_1, denominator_0, denominator_1] = openings.try_into().unwrap();
    LogupGkrRoundProof { numerator_0, numerator_1, denominator_0, denominator_1, sumcheck_proof }
}

/// Proves a single interaction-combining GKR round on the device.
///
/// After the row tree finishes, the interaction dimension is combined with its own standalone GKR
/// rounds (reducing the `2^(k_full + 1)` base toward the 2-entry circuit output). Each such round
/// is a degree-3 sumcheck over a fully-materialized power-of-two `[4, 2^v]` interaction layer
/// with no row dimension, so it reuses the device `materialized_round_sumcheck` (whose
/// `InteractionsLayer` path is exercised via `sum_as_poly`/`fix_and_sum`/`fix_last_variable`).
fn prove_interaction_round<C: FieldChallenger<Felt>>(
    layer: Tensor<Ext, TaskScope>,
    eval_point: &Point<Ext>,
    numerator_eval: Ext,
    denominator_eval: Ext,
    challenger: &mut C,
) -> LogupGkrRoundProof<Ext> {
    let lambda = challenger.sample_ext_element::<Ext>();
    let claim = numerator_eval * lambda + denominator_eval;

    let backend = layer.backend().clone();
    let point = DevicePoint::from_host(eval_point, &backend).unwrap().into_inner();
    let eq_interaction = DevicePoint::new(point).partial_lagrange();
    // A 0-variable row eq (a single `1`). It is never read in the `InteractionsLayer` sumcheck
    // path; only its `num_variables() == 0` matters, so the round has exactly
    // `eval_point.dimension()` variables.
    let eq_row = DeviceMle::from_host(&Mle::from(vec![Ext::one()]), &backend).unwrap();

    let sumcheck_poly = LogupRoundPolynomial {
        layer: PolynomialLayer::InteractionsLayer(layer),
        eq_row,
        eq_interaction,
        lambda,
        eq_adjustment: Ext::one(),
        padding_adjustment: Ext::one(),
        point: eval_point.clone(),
    };

    let (sumcheck_proof, openings) =
        sumcheck::materialized_round_sumcheck(sumcheck_poly, challenger, claim);
    let [numerator_0, numerator_1, denominator_0, denominator_1] = openings.try_into().unwrap();
    LogupGkrRoundProof { numerator_0, numerator_1, denominator_0, denominator_1, sumcheck_proof }
}

pub fn prove_round<'a, C: FieldChallenger<Felt>>(
    circuit: GkrCircuitLayer<'a>,
    eval_point: &Point<Ext>,
    numerator_eval: Ext,
    denominator_eval: Ext,
    challenger: &mut C,
) -> LogupGkrRoundProof<Ext> {
    match circuit {
        GkrCircuitLayer::Materialized(layer) => prove_materialized_round(
            layer,
            eval_point,
            numerator_eval,
            denominator_eval,
            challenger,
        ),
        GkrCircuitLayer::FirstLayer(layer) => {
            prove_first_round(layer, eval_point, numerator_eval, denominator_eval, challenger)
        }
        GkrCircuitLayer::FirstLayerVirtual(_) => unreachable!(),
    }
}

/// Proves the GKR circuit, layer by layer.
#[instrument(skip_all, level = "debug")]
pub fn prove_gkr_circuit<'a, C: FieldChallenger<Felt>>(
    numerator_value: Ext,
    denominator_value: Ext,
    eval_point: Point<Ext>,
    mut circuit: LogUpCudaCircuit<'a, TaskScope>,
    challenger: &mut C,
    recompute_first_layer: bool,
) -> (Point<Ext>, Vec<LogupGkrRoundProof<Ext>>) {
    let mut round_proofs = Vec::new();
    // Follow the GKR protocol layer by layer.
    let mut numerator_eval = numerator_value;
    let mut denominator_eval = denominator_value;
    let mut eval_point = eval_point;
    while let Some(layer) = circuit.next(recompute_first_layer) {
        // Generate the round proof.
        let round_proof =
            prove_round(layer, &eval_point, numerator_eval, denominator_eval, challenger);

        // Observe the prover message.
        challenger.observe_ext_element::<Ext>(round_proof.numerator_0);
        challenger.observe_ext_element::<Ext>(round_proof.numerator_1);
        challenger.observe_ext_element::<Ext>(round_proof.denominator_0);
        challenger.observe_ext_element::<Ext>(round_proof.denominator_1);

        // Get the evaluation point for the claims of the next round.
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
    (eval_point, round_proofs)
}

/// End-to-end proves lookups for a given trace.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn prove_logup_gkr<GC, SC>(
    chips: &BTreeSet<Chip<Felt, SC::Air>>,
    all_interactions: BTreeMap<String, Arc<Interactions<Felt, TaskScope>>>,
    jagged_trace_data: &JaggedTraceMle<Felt, TaskScope>,
    public_values: Vec<Felt>,
    global_challenges: Option<(Ext, Point<Ext>)>,
    options: CudaLogUpGkrOptions,
    challenger: &mut GC::Challenger,
) -> (LogupGkrProof<Felt, Ext>, Option<Ext>)
where
    GC: IopCtx<F = Felt, EF = Ext>,
    SC: ShardContext<GC>,
    GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
{
    let CudaLogUpGkrOptions { recompute_first_layer, num_row_variables } = options;
    let backend = jagged_trace_data.backend().clone();

    let beta_seed_dim = beta_seed_dim_for_scope(
        chips.iter(),
        InteractionScope::Local,
        pv_interaction_max_arity::<Record<GC, SC>>(),
    );

    let witness = GrindingPowCudaProver::grind(challenger, GKR_GRINDING_BITS, &backend);

    // Sample the local logup challenges.
    let alpha = challenger.sample_ext_element::<GC::EF>();
    let beta_seed =
        (0..beta_seed_dim).map(|_| challenger.sample_ext_element::<GC::EF>()).collect::<Point<_>>();
    let pv_challenge = challenger.sample_ext_element::<GC::EF>();

    let has_global_round = global_challenges.is_some();

    // On machines with a global round, compute the global-scope public-value digest under the
    // global challenge pair; it folds into the shard's global cumulative sum.
    let global_pv_digest = global_challenges.as_ref().map(|global_challenges| {
        let (_, global_pv_digest) = LogUpGkrVerifier::<GC, SC>::verify_public_values(
            pv_challenge,
            &alpha,
            &beta_seed,
            Some(global_challenges),
            &public_values,
        )
        .expect("the prover's public values must satisfy the public-value constraints");
        global_pv_digest
    });

    let (global_alpha, global_beta_seed) =
        global_challenges.clone().unwrap_or_else(|| (alpha, beta_seed.clone()));

    // The grouped interaction-dimension shape, mirroring the native verifier's derivation: the
    // local-scope interactions form the low block `[0, num_local)`, the slots
    // `[num_local, 2^k_local)` are padding, and the global-scope interactions form the block
    // starting at `2^k_local`, followed by padding up to `2^k_full`.
    let num_local = chips
        .iter()
        .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
        .filter(|interaction| interaction.scope == InteractionScope::Local)
        .count();
    let num_global =
        chips.iter().map(|chip| chip.sends().len() + chip.receives().len()).sum::<usize>()
            - num_local;
    assert!(
        has_global_round || num_global == 0,
        "global-scope interactions require a global round"
    );
    let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
    let k_full = if num_global > 0 {
        ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
    } else {
        k_local
    };

    // Run the GKR circuit and get the base output: the device circuit reduces the row dimension
    // all the way down but leaves the interaction dimension un-combined, so `base_output` holds
    // the `2^(k_full + 1)` per-interaction fraction pairs in grouped order.
    let (base_output, circuit) = generate_gkr_circuit(
        chips,
        all_interactions,
        jagged_trace_data,
        (alpha, beta_seed),
        (global_alpha, global_beta_seed),
        options,
        backend,
    );

    // Tree-combine the interaction dimension on the device: `il_0` gives the "one entry per
    // interaction" layer, the exposed global outputs are suffix-copied to the host from its
    // global block, and the local tree reduces its `2^k_local` prefix to the 2-entry circuit
    // output.
    let InteractionLayers { mut layers, output: output_host, global_interaction_outputs } =
        build_interaction_layers(base_output, k_full, k_local, num_global);
    assert_eq!(layers.len(), k_local);

    // Observe the circuit output and the exposed global-interaction outputs, at the same
    // transcript positions as the verifier (before the first evaluation point).
    challenger.observe_variable_length_extension_slice(output_host.numerator.guts().as_slice());
    challenger.observe_variable_length_extension_slice(output_host.denominator.guts().as_slice());
    for (global_numerator, global_denominator) in &global_interaction_outputs {
        challenger.observe_ext_element(*global_numerator);
        challenger.observe_ext_element(*global_denominator);
    }

    // The global cumulative sum exposed by the shard: the sum of the exposed global-interaction
    // fractions, plus the global-scope public-value digest. The verifier binds each exposed
    // output to the committed traces through the transition fold, and recomputes this aggregate.
    let global_cumulative_sum = global_pv_digest
        .map(|global_pv_digest| global_output_sum(&global_interaction_outputs) + global_pv_digest);

    // The circuit output is the top `level-1` layer: a single pair of fractions (one variable).
    let initial_number_of_variables = output_host.numerator.num_variables();
    assert_eq!(initial_number_of_variables, 1);
    let first_eval_point = challenger.sample_point::<Ext>(initial_number_of_variables);

    // Compute the first claims from the (size-2) circuit output on the host.
    let mut numerator_eval = output_host.numerator.blocking_eval_at(&first_eval_point)[0];
    let mut denominator_eval = output_host.denominator.blocking_eval_at(&first_eval_point)[0];
    let mut eval_point = first_eval_point;

    // Prove the interaction-combining rounds on the device, back-to-front (the layer under the
    // circuit output first), so reverse the finest-children-first build order. On a global
    // round, the transition fold splices the exposed global outputs into the claim right before
    // the round consuming the "one entry per interaction" layer (the last interaction round);
    // with no global interactions it is a transcript no-op at the same position.
    layers.reverse();
    let num_interaction_rounds = layers.len();
    let mut round_proofs = Vec::with_capacity(num_interaction_rounds + num_row_variables as usize);
    for (i, layer) in layers.into_iter().enumerate() {
        if has_global_round && i == num_interaction_rounds - 1 {
            transition_fold::<GC>(
                k_local,
                k_full,
                &global_interaction_outputs,
                &mut eval_point,
                &mut numerator_eval,
                &mut denominator_eval,
                challenger,
            );
        }

        let round_proof = prove_interaction_round(
            layer,
            &eval_point,
            numerator_eval,
            denominator_eval,
            challenger,
        );

        // Observe the prover message.
        challenger.observe_ext_element::<Ext>(round_proof.numerator_0);
        challenger.observe_ext_element::<Ext>(round_proof.numerator_1);
        challenger.observe_ext_element::<Ext>(round_proof.denominator_0);
        challenger.observe_ext_element::<Ext>(round_proof.denominator_1);

        // Thread the running claim to the next round.
        eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
        let last_coordinate = challenger.sample_ext_element::<Ext>();
        numerator_eval = round_proof.numerator_0
            + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
        denominator_eval = round_proof.denominator_0
            + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
        eval_point.add_dimension_back(last_coordinate);

        round_proofs.push(round_proof);
    }

    // After the interaction rounds `eval_point` has `k_full + 1` coordinates — exactly the input
    // the first (device) row round consumes. Prove the row rounds on the device and append them.
    let (eval_point, row_round_proofs) = prove_gkr_circuit(
        numerator_eval,
        denominator_eval,
        eval_point,
        circuit,
        challenger,
        recompute_first_layer,
    );
    round_proofs.extend(row_round_proofs);

    // Get the evaluations for each chip at the evaluation point of the last round.
    // We accomplish this by doing jagged fix last variable on the evaluation point.
    let eval_point = eval_point.last_k(num_row_variables as usize);
    let host_evaluations = round_batch_evaluations(&eval_point, jagged_trace_data);
    // Trace openings come back round-by-round in `[preprocessed, (global,) main]` order. Split
    // them off positionally; each round's per-chip evaluations are then keyed by chip name, since
    // the rounds walk the trace's table indices in (name) order.
    let mut rounds = host_evaluations.rounds;
    let main: Vec<MleEval<Ext>> = rounds.pop().expect("logup gkr produced no trace-opening rounds");
    let preprocessed: Vec<MleEval<Ext>> = rounds.remove(0);
    let global: Option<Vec<MleEval<Ext>>> = has_global_round.then(|| rounds.remove(0));

    let trace_data = jagged_trace_data.dense();
    let prep_by_name = trace_data
        .preprocessed_table_index
        .keys()
        .map(String::as_str)
        .zip(preprocessed)
        .collect::<BTreeMap<_, _>>();
    let main_by_name = trace_data
        .main_table_index
        .keys()
        .map(String::as_str)
        .zip(main)
        .collect::<BTreeMap<_, _>>();
    let global_by_name = global.map(|global| {
        trace_data
            .global_table_index
            .keys()
            .map(String::as_str)
            .zip(global)
            .collect::<BTreeMap<_, _>>()
    });

    let mut chip_evaluations = BTreeMap::new();

    challenger.observe(Felt::from_canonical_usize(chips.len()));
    for chip in chips.iter() {
        let name = chip.name();
        let main_trace_evaluations =
            main_by_name.get(name).cloned().unwrap_or_else(|| MleEval::from(Vec::new()));
        let preprocessed_trace_evaluations =
            prep_by_name.get(name).cloned().unwrap_or_else(|| MleEval::from(Vec::new()));
        let global_trace_evaluations = global_by_name
            .as_ref()
            .and_then(|m| m.get(name).cloned())
            .unwrap_or_else(|| MleEval::from(Vec::new()));
        let openings = ChipEvaluation {
            main_trace_evaluations,
            preprocessed_trace_evaluations,
            global_trace_evaluations,
        };

        // Observe the openings, in the order `prep, global, main`.
        challenger
            .observe_variable_length_extension_slice(&openings.preprocessed_trace_evaluations);
        if has_global_round {
            challenger.observe_variable_length_extension_slice(&openings.global_trace_evaluations);
        }
        challenger.observe_variable_length_extension_slice(&openings.main_trace_evaluations);

        chip_evaluations.insert(name.to_string(), openings);
    }

    let logup_evaluations = LogUpEvaluations { point: eval_point, chip_openings: chip_evaluations };

    let proof = LogupGkrProof {
        circuit_output: output_host,
        global_interaction_outputs,
        round_proofs,
        logup_evaluations,
        witness,
    };
    (proof, global_cumulative_sum)
}

#[cfg(test)]
mod tests {
    use crate::utils::{
        generate_test_data, get_polys_from_layer, jagged_first_gkr_layer_to_device,
        jagged_gkr_layer_to_device, jagged_gkr_layer_to_host, random_first_layer, GkrTestData,
    };
    use itertools::Itertools;
    use serial_test::serial;
    use slop_challenger::{FieldChallenger, IopCtx};
    use slop_futures::queue::WorkerQueue;
    use slop_multilinear::Mle;
    use slop_sumcheck::partially_verify_sumcheck_proof;
    use sp1_core_machine::io::SP1Stdin;
    use sp1_core_machine::riscv::RiscvAir;
    use sp1_gpu_cudart::{run_sync_in_place, DevicePoint, PinnedBuffer};
    use sp1_gpu_jagged_tracegen::{
        full_tracegen,
        test_utils::tracegen_setup::{self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT},
        CORE_MAX_TRACE_SIZE,
    };
    use sp1_gpu_utils::TestGC;
    use sp1_hypercube::{observe_global_challenge, prover::ProverSemaphore, SP1SC};
    use std::sync::Arc;

    use crate::execution::{extract_outputs, gkr_transition, layer_transition};

    use super::*;

    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    #[serial]
    fn test_logup_gkr_circuit_transition() {
        let mut rng = StdRng::seed_from_u64(1);

        let interaction_row_counts: Vec<u32> =
            vec![(1 << 10) + 32, (1 << 10) - 2, 1 << 6, 1 << 8, (1 << 10) + 2];
        let (layer, test_data) = generate_test_data(&mut rng, interaction_row_counts, None);
        let GkrTestData { numerator_0, numerator_1, denominator_0, denominator_1 } = test_data;

        let GkrLayer { jagged_mle, num_interaction_variables, num_row_variables } = layer;

        run_sync_in_place(move |t| {
            let jagged_mle = jagged_gkr_layer_to_device(jagged_mle, &t);

            let layer = GkrLayer { jagged_mle, num_interaction_variables, num_row_variables };

            // Test a single transition.
            let next_layer = layer_transition(&layer);

            let GkrLayer {
                jagged_mle: next_layer_data,
                num_interaction_variables,
                num_row_variables,
            } = next_layer;

            let next_layer_data = jagged_gkr_layer_to_host(next_layer_data);

            let next_layer_host = GkrLayer {
                jagged_mle: next_layer_data,
                num_interaction_variables,
                num_row_variables,
            };

            let next_layer_data = get_polys_from_layer(&next_layer_host);

            let next_numerator_0 = next_layer_data.numerator_0;
            let next_numerator_1 = next_layer_data.numerator_1;
            let next_denominator_0 = next_layer_data.denominator_0;
            let next_denominator_1 = next_layer_data.denominator_1;

            let next_n_values = next_numerator_0
                .guts()
                .as_slice()
                .iter()
                .interleave(next_numerator_1.guts().as_slice())
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(next_n_values.len(), numerator_0.guts().as_slice().len());
            let next_d_values = next_denominator_0
                .guts()
                .as_slice()
                .iter()
                .interleave(next_denominator_1.guts().as_slice())
                .copied()
                .collect::<Vec<_>>();

            for (i, (((((next_n, next_d), n_0), n_1), d_0), d_1)) in next_n_values
                .iter()
                .zip_eq(next_d_values)
                .zip_eq(numerator_0.guts().as_slice())
                .zip_eq(numerator_1.guts().as_slice())
                .zip_eq(denominator_0.guts().as_slice())
                .zip_eq(denominator_1.guts().as_slice())
                .enumerate()
            {
                assert_eq!(next_d, *d_0 * *d_1, "failed at index {i}");
                assert_eq!(*next_n, *n_0 * *d_1 + *n_1 * *d_0, "failed at index {i}");
            }
        })
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_logup_gkr_round_prover() {
        let mut rng = StdRng::seed_from_u64(1);

        let get_challenger = move || TestGC::default_challenger();

        let interaction_row_counts: Vec<u32> = vec![
            99064, 99064, 99064, 188896, 188896, 188896, 85256, 107776, 107776, 25112, 25112,
            25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112,
            25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112, 25112,
            25112, 25112, 25112, 25112, 25112, 25112, 56360, 56360, 56360, 56360, 56360, 56360, 4,
            169496, 169496, 169496, 169496, 169496,
        ];
        let layer = random_first_layer(&mut rng, interaction_row_counts, Some(19));
        println!("generated test data");

        let FirstGkrLayer { jagged_mle, num_interaction_variables, num_row_variables } = layer;

        println!("num row variables: {}", num_row_variables);

        let first_eval_point = Point::<Ext>::rand(&mut rng, num_interaction_variables + 1);

        run_sync_in_place(move |t| {
            let jagged_mle = jagged_first_gkr_layer_to_device(jagged_mle, &t);

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
            println!("trace generation time: {:?}", time.elapsed());

            let time = std::time::Instant::now();
            layers.reverse();
            let first_layer =
                if let GkrCircuitLayer::Materialized(first_layer) = layers.first().unwrap() {
                    first_layer
                } else {
                    panic!("first layer not correct");
                };
            assert_eq!(first_layer.num_row_variables, 1);

            let output = extract_outputs(first_layer, num_interaction_variables);
            println!("time to extract values: {:?}", time.elapsed());

            let first_point_device =
                DevicePoint::from_host(&first_eval_point, &t).unwrap().into_inner();
            let device_numerator = output.numerator;
            let device_denominator = output.denominator;
            let first_point_eq = DevicePoint::new(first_point_device).partial_lagrange();
            let first_numerator_eval =
                device_numerator.eval_at_eq(&first_point_eq).to_host_vec().unwrap()[0];
            let first_denominator_eval =
                device_denominator.eval_at_eq(&first_point_eq).to_host_vec().unwrap()[0];

            let mut challenger = get_challenger();
            t.synchronize_blocking().unwrap();
            let time = std::time::Instant::now();
            let mut round_proofs = Vec::new();
            // Follow the GKR protocol layer by layer.
            let mut numerator_eval = first_numerator_eval;
            let mut denominator_eval = first_denominator_eval;
            let mut eval_point = first_eval_point.clone();

            for layer in layers {
                let round_proof = prove_round(
                    layer,
                    &eval_point,
                    numerator_eval,
                    denominator_eval,
                    &mut challenger,
                );

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
            println!("proof generation time: {:?}", time.elapsed());

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
                let denominator_sumcheck_eval =
                    round_proof.denominator_0 * round_proof.denominator_1;
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
        })
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_logup_gkr_e2e() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (machine, record, program) =
            rt.block_on(tracegen_setup::setup(&test_artifacts::FIBONACCI_ELF, SP1Stdin::new()));

        run_sync_in_place(|scope| {
            // *********** Generate traces using the host tracegen. ***********
            let capacity = CORE_MAX_TRACE_SIZE as usize;
            let buffer = PinnedBuffer::<Felt>::with_capacity(capacity);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = rt.block_on(queue.pop()).unwrap();
            let (public_values, jagged_trace_data, shard_chips, _permit) =
                rt.block_on(full_tracegen(
                    &machine,
                    program.clone(),
                    Arc::new(record),
                    &buffer,
                    CORE_MAX_TRACE_SIZE as usize,
                    LOG_STACKING_HEIGHT,
                    CORE_MAX_LOG_ROW_COUNT,
                    &scope,
                    ProverSemaphore::new(1),
                    true,
                ));

            // *********** Generate LogupGKR traces and prove end to end ***********
            let challenger = TestGC::default_challenger();

            let shard_chips = machine.smallest_cluster(&shard_chips).unwrap();

            let mut all_interactions = BTreeMap::new();
            for chip in shard_chips.iter() {
                let interactions = Interactions::new(chip.sends(), chip.receives());
                let device_interactions = interactions.copy_to_device(&scope).unwrap();
                all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
            }

            let global_beta_seed_dim = beta_seed_dim_for_scope(
                machine.chips().iter(),
                InteractionScope::Global,
                pv_interaction_max_arity::<Record<TestGC, SP1SC<TestGC, RiscvAir<Felt>>>>(),
            );
            let mut base_challenger = challenger.clone();
            let global_challenges =
                observe_global_challenge::<TestGC>(None, global_beta_seed_dim, &mut base_challenger);

            let mut prover_challenger = base_challenger.clone();
            let (proof, global_cumulative_sum) =
                super::prove_logup_gkr::<TestGC, SP1SC<TestGC, RiscvAir<Felt>>>(
                    shard_chips,
                    all_interactions,
                    &jagged_trace_data,
                    public_values.clone(),
                    Some(global_challenges.clone()),
                    CudaLogUpGkrOptions {
                        recompute_first_layer: true,
                        num_row_variables: CORE_MAX_LOG_ROW_COUNT,
                    },
                    &mut prover_challenger,
                );
            let prover_challenge: Ext = prover_challenger.sample_ext_element();

            let degrees = shard_chips
                .iter()
                .map(|c| {
                    let poly_size = jagged_trace_data
                        .main_poly_height(c.name())
                        .or_else(|| jagged_trace_data.global_poly_height(c.name()))
                        .unwrap();

                    let threshold_point =
                        Point::<Felt>::from_usize(poly_size, CORE_MAX_LOG_ROW_COUNT as usize + 1);
                    (c.name().to_string(), threshold_point)
                })
                .collect();

            let mut verifier_challenger = base_challenger.clone();
            sp1_hypercube::LogUpGkrVerifier::<TestGC, SP1SC<TestGC, RiscvAir<Felt>>>::verify_logup_gkr(
                shard_chips,
                &degrees,
                CORE_MAX_LOG_ROW_COUNT as usize,
                Some(&global_challenges),
                global_cumulative_sum,
                &proof,
                &public_values,
                &mut verifier_challenger,
            )
            .unwrap();

            // Assert the prover and verifier have the same challenger state.
            let verifier_challenge: Ext = verifier_challenger.sample_ext_element();
            assert_eq!(verifier_challenge, prover_challenge);

            // Tampering with an exposed global-interaction output must be rejected: the
            // transition fold binds the exposed values to the committed traces (mirrors
            // `test_two_stream_gkr_rounds_tampered_global_output` in `sp1-hypercube`).
            assert!(!proof.global_interaction_outputs.is_empty());
            let mut tampered_proof = proof.clone();
            tampered_proof.global_interaction_outputs[0].0 += Ext::one();
            let mut tampered_challenger = base_challenger.clone();
            sp1_hypercube::LogUpGkrVerifier::<TestGC, SP1SC<TestGC, RiscvAir<Felt>>>::verify_logup_gkr(
                shard_chips,
                &degrees,
                CORE_MAX_LOG_ROW_COUNT as usize,
                Some(&global_challenges),
                global_cumulative_sum,
                &tampered_proof,
                &public_values,
                &mut tampered_challenger,
            )
            .unwrap_err();
        })
        .unwrap();
    }
}
