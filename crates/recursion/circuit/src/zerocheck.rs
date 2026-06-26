use std::{collections::BTreeSet, ops::Deref};

use crate::{
    challenger::{CanObserveVariable, FieldChallengerVariable},
    shard::RecursiveShardVerifier,
    sumcheck::verify_sumcheck,
    symbolic::IntoSymbolic,
    CircuitConfig, SP1FieldConfigVariable,
};
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::{full_geq, Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use sp1_hypercube::{
    air::MachineAir, Chip, ChipOpenedValues, GenericVerifierConstraintFolder, LogUpEvaluations,
    OpeningShapeError, ShardOpenedValues,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    ir::Felt,
    prelude::{Builder, Ext, SymbolicExt},
};

pub type RecursiveVerifierConstraintFolder<'a> = GenericVerifierConstraintFolder<
    'a,
    SP1Field,
    SP1ExtensionField,
    Felt<SP1Field>,
    Ext<SP1Field, SP1ExtensionField>,
    SymbolicExt<SP1Field, SP1ExtensionField>,
>;

#[allow(clippy::type_complexity)]
pub fn eval_constraints<C: CircuitConfig, SC: SP1FieldConfigVariable<C>, A>(
    builder: &mut Builder<C>,
    chip: &Chip<SP1Field, A>,
    opening: &ChipOpenedValues<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>,
    alpha: Ext<SP1Field, SP1ExtensionField>,
    public_values: &[Felt<SP1Field>],
) -> Ext<SP1Field, SP1ExtensionField>
where
    A: MachineAir<SP1Field> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    let mut folder = RecursiveVerifierConstraintFolder {
        preprocessed: RowMajorMatrixView::new_row(&opening.preprocessed.local),
        global: RowMajorMatrixView::new_row(&opening.global.local),
        main: RowMajorMatrixView::new_row(&opening.main.local),
        public_values,
        alpha,
        accumulator: SymbolicExt::zero(),
        _marker: std::marker::PhantomData,
    };

    chip.eval(&mut folder);
    builder.eval(folder.accumulator)
}

/// Compute the padded row adjustment for a chip.
pub fn compute_padded_row_adjustment<C: CircuitConfig, A>(
    builder: &mut Builder<C>,
    chip: &Chip<SP1Field, A>,
    alpha: Ext<SP1Field, SP1ExtensionField>,
    public_values: &[Felt<SP1Field>],
) -> Ext<SP1Field, SP1ExtensionField>
where
    A: MachineAir<SP1Field> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    let zero = builder.constant(SP1ExtensionField::zero());
    let dummy_preprocessed_trace = vec![zero; chip.preprocessed_width()];
    let dummy_global_trace = vec![zero; chip.global_width()];
    let dummy_main_trace = vec![zero; chip.width()];

    let mut folder = RecursiveVerifierConstraintFolder {
        preprocessed: RowMajorMatrixView::new_row(&dummy_preprocessed_trace),
        global: RowMajorMatrixView::new_row(&dummy_global_trace),
        main: RowMajorMatrixView::new_row(&dummy_main_trace),
        alpha,
        accumulator: SymbolicExt::zero(),
        public_values,
        _marker: std::marker::PhantomData,
    };

    chip.eval(&mut folder);
    builder.eval(folder.accumulator)
}

#[allow(clippy::type_complexity)]
pub fn verify_opening_shape<C: CircuitConfig, A>(
    chip: &Chip<SP1Field, A>,
    opening: &ChipOpenedValues<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>,
) -> Result<(), OpeningShapeError>
where
    A: MachineAir<SP1Field> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    // Verify that the preprocessed width matches the expected value for the chip.
    if opening.preprocessed.local.len() != chip.preprocessed_width() {
        return Err(OpeningShapeError::PreprocessedWidthMismatch(
            chip.preprocessed_width(),
            opening.preprocessed.local.len(),
        ));
    }

    // Verify that the main width matches the expected value for the chip.
    if opening.main.local.len() != chip.width() {
        return Err(OpeningShapeError::MainWidthMismatch(chip.width(), opening.main.local.len()));
    }

    Ok(())
}

impl<GC, C, A> RecursiveShardVerifier<GC, A, C>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    C: CircuitConfig,
    A: MachineAir<SP1Field>,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_zerocheck(
        &self,
        builder: &mut Builder<C>,
        shard_chips: &BTreeSet<Chip<SP1Field, A>>,
        opened_values: &ShardOpenedValues<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>,
        gkr_evaluations: &LogUpEvaluations<Ext<SP1Field, SP1ExtensionField>>,
        zerocheck_proof: &PartialSumcheckProof<Ext<SP1Field, SP1ExtensionField>>,
        public_values: &[Felt<SP1Field>],
        challenger: &mut GC::FriChallengerVariable,
        has_global_round: bool,
    ) where
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
    {
        let zero: Ext<SP1Field, SP1ExtensionField> = builder.constant(SP1ExtensionField::zero());
        let one: Ext<SP1Field, SP1ExtensionField> = builder.constant(SP1ExtensionField::one());
        let mut rlc_eval: Ext<SP1Field, SP1ExtensionField> = zero;

        let alpha = challenger.sample_ext(builder);
        let gkr_batch_open_challenge: SymbolicExt<SP1Field, SP1ExtensionField> =
            challenger.sample_ext(builder).into();
        let lambda = challenger.sample_ext(builder);

        // Get the value of eq(zeta, sumcheck's reduced point).
        let point_symbolic =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
                &zerocheck_proof.point_and_eval.0,
            );

        let gkr_evaluations_point = IntoSymbolic::<C>::as_symbolic(&gkr_evaluations.point);

        let zerocheck_eq_val = Mle::full_lagrange_eval(&gkr_evaluations_point, &point_symbolic);

        let max_elements = shard_chips
            .iter()
            .map(|chip| chip.width() + chip.preprocessed_width() + chip.global_width())
            .max()
            .unwrap_or(0);

        let gkr_batch_open_challenge_powers =
            gkr_batch_open_challenge.powers().skip(1).take(max_elements).collect::<Vec<_>>();

        for (chip, openings) in shard_chips.iter().zip_eq(opened_values.chips.values()) {
            // Verify the shape of the opening arguments matches the expected values.
            verify_opening_shape::<C, A>(chip, openings).unwrap();

            let dimension = zerocheck_proof.point_and_eval.0.dimension();

            assert_eq!(dimension, self.pcs_verifier.max_log_row_count);

            let mut proof_point_extended = point_symbolic.clone();
            proof_point_extended.add_dimension(zero.into());
            let degree_symbolic_ext: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
                openings.degree.iter().map(|x| SymbolicExt::from(*x)).collect::<Point<_>>();
            degree_symbolic_ext.iter().enumerate().for_each(|(i, x)| {
                builder.assert_ext_eq(*x * (*x - one), zero);
                if i >= 1 {
                    builder.assert_ext_eq(*x * *degree_symbolic_ext.first().unwrap(), zero);
                }
            });
            let geq_val = full_geq(&degree_symbolic_ext, &proof_point_extended);

            let padded_row_adjustment =
                compute_padded_row_adjustment(builder, chip, alpha, public_values);

            let constraint_eval =
                eval_constraints::<C, GC, A>(builder, chip, openings, alpha, public_values)
                    - padded_row_adjustment * geq_val;

            let openings_batch = openings
                .main
                .local
                .iter()
                .chain(openings.preprocessed.local.iter())
                .chain(openings.global.local.iter())
                .copied()
                .zip(
                    gkr_batch_open_challenge_powers
                        .iter()
                        .take(
                            openings.main.local.len()
                                + openings.preprocessed.local.len()
                                + openings.global.local.len(),
                        )
                        .copied(),
                )
                .map(|(opening, power)| opening * power)
                .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>();

            rlc_eval = builder
                .eval(rlc_eval * lambda + zerocheck_eq_val * (constraint_eval + openings_batch));
        }

        builder.assert_ext_eq(rlc_eval, zerocheck_proof.point_and_eval.1);

        let zerocheck_sum_modifications_from_gkr = gkr_evaluations
            .chip_openings
            .values()
            .map(|chip_evaluation| {
                chip_evaluation
                    .main_trace_evaluations
                    .deref()
                    .iter()
                    .copied()
                    .chain(
                        chip_evaluation
                            .preprocessed_trace_evaluations
                            .as_ref()
                            .iter()
                            .flat_map(|&evals| evals.deref().iter().copied()),
                    )
                    .chain(
                        chip_evaluation
                            .global_trace_evaluations
                            .as_ref()
                            .iter()
                            .flat_map(|&evals| evals.deref().iter().copied()),
                    )
                    .zip(gkr_batch_open_challenge_powers.iter().copied())
                    .map(|(opening, power)| opening * power)
                    .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>()
            })
            .collect::<Vec<_>>();

        let zerocheck_sum_modification: SymbolicExt<SP1Field, SP1ExtensionField> =
            zerocheck_sum_modifications_from_gkr
                .iter()
                .fold(zero.into(), |acc, modification| lambda * acc + *modification);

        // Verify that the rlc claim is zero.
        builder.assert_ext_eq(zerocheck_proof.claimed_sum, zerocheck_sum_modification);

        // Verify the zerocheck proof.
        verify_sumcheck::<C, GC>(builder, challenger, zerocheck_proof);

        // Observe the openings
        let len_felt: Felt<_> = builder.constant(SP1Field::from_canonical_usize(shard_chips.len()));
        challenger.observe(builder, len_felt);
        for opening in opened_values.chips.values() {
            challenger
                .observe_variable_length_extension_slice(builder, &opening.preprocessed.local);
            if has_global_round {
                challenger.observe_variable_length_extension_slice(builder, &opening.global.local);
            }
            challenger.observe_variable_length_extension_slice(builder, &opening.main.local);
        }
    }
}

// TODO: Add tests back.
// #[cfg(test)]
// mod tests {
//     use std::{marker::PhantomData, sync::Arc};

//     use slop_algebra::extension::BinomialExtensionField;
//     use sp1_primitives::SP1DiffusionMatrix;
//     use slop_basefold::{BasefoldVerifier, SP1BasefoldConfig};
//     use slop_jagged::SP1InnerPcs;
//     use sp1_hypercube::inner_perm;
//     use sp1_core_executor::{Program, SP1Context};
//     use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir, utils::prove_core};
//     use sp1_recursion_compiler::{
//         circuit::{AsmCompiler, AsmConfig},
//         config::InnerConfig,
//     };
//     use sp1_recursion_executor::Runtime;
//     use sp1_hypercube::{prover::CpuProver, SP1CoreOpts, ShardVerifier};

//     use crate::{
//         basefold::{stacked::RecursiveStackedPcsVerifier, tcs::RecursiveMerkleTreeTcs},
//         challenger::DuplexChallengerVariable,
//         jagged::{
//             RecursiveJaggedConfigImpl, RecursiveJaggedEvalSumcheckConfig,
//             RecursiveJaggedPcsVerifier,
//         },
//         witness::Witnessable,
//     };

//     use super::*;

//     use sp1_primitives::SP1Field;
//    type F = SP1Field;
//     type SC = SP1InnerPcs;
//     type JC = RecursiveJaggedConfigImpl<
//         C,
//         SC,
//         RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
//     >;
//     type C = InnerConfig;
//     type EF = BinomialExtensionField<SP1Field, 4>;
//     type A = RiscvAir<SP1Field>;

//     #[tokio::test]
//     async fn test_zerocheck() {
//         let program = Program::from(test_artifacts::FIBONACCI_ELF).unwrap();
//         let log_blowup = 1;
//         let log_stacking_height = 21;
//         let max_log_row_count = 21;
//         let machine = RiscvAir::machine();
//         let verifier = ShardVerifier::from_basefold_parameters(
//             log_blowup,
//             log_stacking_height,
//             max_log_row_count,
//             machine.clone(),
//         );
//         let prover = CpuProver::new(verifier.clone());

//         let (pk, _) = prover.setup(Arc::new(program.clone())).await;

//         let challenger = verifier.pcs_verifier.challenger();

//         let (proof, _) = prove_core(
//             Arc::new(prover),
//             Arc::new(pk),
//             Arc::new(program.clone()),
//             &SP1Stdin::new(),
//             SP1CoreOpts::default(),
//             SP1Context::default(),
//             challenger,
//         )
//         .await
//         .unwrap();

//         let shard_proof = proof.shard_proofs[0].clone();
//         let challenger_state = shard_proof.testing_data.challenger_state.clone();

//         let mut builder = Builder::<C>::default();

//         let mut challenger_variable =
//             DuplexChallengerVariable::from_challenger(&mut builder, &challenger_state);

//         let shard_proof_variable = shard_proof.read(&mut builder);

//         let gkr_points_variable = shard_proof.testing_data.gkr_points.read(&mut builder);
//         let gkr_column_openings_variable = shard_proof
//             .gkr_proofs
//             .iter()
//             .map(|gkr_proof| {
//                 let (main_openings, preprocessed_openings) = &gkr_proof.column_openings;
//                 let main_openings_variable = main_openings.read(&mut builder);
//                 let preprocessed_openings_variable: MleEval<Ext<_, _>> = preprocessed_openings
//                     .as_ref()
//                     .map(MleEval::to_vec)
//                     .unwrap_or_default()
//                     .read(&mut builder)
//                     .into();
//                 (main_openings_variable, preprocessed_openings_variable)
//             })
//             .collect::<Vec<_>>();

//         let verifier = BasefoldVerifier::<SP1BasefoldConfig>::new(log_blowup);
//         let recursive_verifier = RecursiveBasefoldVerifier::<RecursiveBasefoldConfigImpl<C, SC>>
// {             fri_config: verifier.fri_config,
//             tcs: RecursiveMerkleTreeTcs::<C, SC>(PhantomData),
//         };
//         let recursive_verifier =
//             RecursiveStackedPcsVerifier::new(recursive_verifier, log_stacking_height);

//         let recursive_jagged_verifier = RecursiveJaggedPcsVerifier::<
//             SC,
//             C,
//             RecursiveJaggedConfigImpl<
//                 C,
//                 SC,
//                 RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
//             >,
//         > { stacked_pcs_verifier: recursive_verifier, max_log_row_count, jagged_evaluator:
//         > RecursiveJaggedEvalSumcheckConfig::<SP1InnerPcs>(PhantomData),
//         };

//         let stark_verifier = StarkVerifier::<A, SC, C, JC> {
//             machine,
//             pcs_verifier: recursive_jagged_verifier,
//             _phantom: std::marker::PhantomData,
//         };

//         stark_verifier.verify_zerocheck(
//             &mut builder,
//             &mut challenger_variable,
//             &shard_proof_variable.opened_values,
//             &shard_proof_variable.zerocheck_proof,
//             &gkr_points_variable,
//             &gkr_column_openings_variable,
//             &shard_proof_variable.public_values,
//         );

//         let mut witness_stream = Vec::new();
//         Witnessable::<AsmConfig<F, EF>>::write(&shard_proof, &mut witness_stream);
//         Witnessable::<AsmConfig<F, EF>>::write(
//             &shard_proof.testing_data.gkr_points,
//             &mut witness_stream,
//         );
//         shard_proof.gkr_proofs.iter().for_each(|gkr_proof| {
//             let (main_openings, preprocessed_openings) = &gkr_proof.column_openings;
//             Witnessable::<AsmConfig<F, EF>>::write(main_openings, &mut witness_stream);
//             let preprocessed_openings_unwrapped: MleEval<_> =
//                 preprocessed_openings.as_ref().map(MleEval::to_vec).unwrap_or_default().into();
//             Witnessable::<AsmConfig<F, EF>>::write(
//                 &preprocessed_openings_unwrapped,
//                 &mut witness_stream,
//             );
//         });

//         let block = builder.into_root_block();
//         let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
//         let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
//         let mut executor =
//             Runtime::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
//         executor.witness_stream = witness_stream.into();
//         executor.run().unwrap();

//         // Test for a bad zerocheck proof.
//         let mut invalid_shard_proof = shard_proof.clone();
//         invalid_shard_proof.zerocheck_proof.univariate_polys[0].coefficients[0] += EF::one();
//         let mut witness_stream = Vec::new();
//         Witnessable::<AsmConfig<F, EF>>::write(&invalid_shard_proof, &mut witness_stream);
//         Witnessable::<AsmConfig<F, EF>>::write(
//             &invalid_shard_proof.testing_data.gkr_points,
//             &mut witness_stream,
//         );
//         invalid_shard_proof.gkr_proofs.iter().for_each(|gkr_proof| {
//             let (main_openings, preprocessed_openings) = &gkr_proof.column_openings;
//             Witnessable::<AsmConfig<F, EF>>::write(main_openings, &mut witness_stream);
//             let preprocessed_openings_unwrapped: MleEval<_> =
//                 preprocessed_openings.as_ref().map(MleEval::to_vec).unwrap_or_default().into();
//             Witnessable::<AsmConfig<F, EF>>::write(
//                 &preprocessed_openings_unwrapped,
//                 &mut witness_stream,
//             );
//         });
//         let mut executor = Runtime::<F, EF, SP1DiffusionMatrix>::new(program,
// inner_perm());         executor.witness_stream = witness_stream.into();
//         executor.run().expect_err("invalid proof should not be verified");
//     }
// }
