use std::{iter::repeat_n, marker::PhantomData};

use itertools::{izip, Itertools};
use slop_algebra::AbstractField;
use slop_jagged::{JaggedLittlePolynomialVerifierParams, JaggedSumcheckEvalProof};
use slop_multilinear::{Mle, MleEval, Point};
use slop_sumcheck::PartialSumcheckProof;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, Felt, SymbolicExt, SymbolicFelt},
};

use crate::{
    basefold::{
        stacked::{RecursiveStackedPcsProof, RecursiveStackedPcsVerifier},
        RecursiveBasefoldProof, RecursiveBasefoldVerifier,
    },
    challenger::FieldChallengerVariable,
    sumcheck::{evaluate_mle_ext, verify_sumcheck},
    CircuitConfig, SP1FieldConfigVariable,
};

use super::jagged_eval::{RecursiveJaggedEvalConfig, RecursiveJaggedEvalSumcheckConfig};

pub struct RecursivePcsImpl<C, SC, P> {
    _marker: PhantomData<(C, SC, P)>,
}

pub struct JaggedPcsProofVariable<Proof, Digest> {
    pub params: JaggedLittlePolynomialVerifierParams<Felt<SP1Field>>,
    pub sumcheck_proof: PartialSumcheckProof<Ext<SP1Field, SP1ExtensionField>>,
    pub jagged_eval_proof: JaggedSumcheckEvalProof<Ext<SP1Field, SP1ExtensionField>>,
    pub pcs_proof: RecursiveStackedPcsProof<Proof, SP1Field, SP1ExtensionField>,
    pub column_counts: Vec<Vec<usize>>,
    pub row_counts: Vec<Vec<Felt<SP1Field>>>,
    pub original_commitments: Vec<Digest>,
    pub expected_eval: Ext<SP1Field, SP1ExtensionField>,
}

#[derive(Clone)]
pub struct RecursiveJaggedPcsVerifier<SC: SP1FieldConfigVariable<C>, C: CircuitConfig> {
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<RecursiveBasefoldVerifier<C, SC>>,
    pub max_log_row_count: usize,
    pub jagged_evaluator: RecursiveJaggedEvalSumcheckConfig<SC>,
}

impl<SC: SP1FieldConfigVariable<C>, C: CircuitConfig> RecursiveJaggedPcsVerifier<SC, C> {
    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluations(
        &self,
        builder: &mut Builder<C>,
        commitments: &[SC::DigestVariable],
        point: Point<Ext<SP1Field, SP1ExtensionField>>,
        evaluation_claims: &[MleEval<Ext<SP1Field, SP1ExtensionField>>],
        proof: &JaggedPcsProofVariable<RecursiveBasefoldProof<C, SC>, SC::DigestVariable>,
        insertion_points: &[usize],
        challenger: &mut SC::FriChallengerVariable,
    ) -> Vec<Felt<SP1Field>> {
        let JaggedPcsProofVariable {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            params,
            column_counts,
            original_commitments,
            expected_eval,
            ..
        } = proof;
        let num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2();

        let z_col =
            (0..num_col_variables).map(|_| challenger.sample_ext(builder)).collect::<Point<_>>();

        let z_row = point;

        // Collect the claims for the different polynomials.
        let mut column_claims = evaluation_claims.iter().flatten().copied().collect::<Vec<_>>();

        let added_columns: Vec<usize> =
            column_counts.iter().map(|cc| cc[cc.len() - 2] + 1).collect();
        // For each commit, Rizz needed a commitment to a vector of length a multiple of
        // 1 << self.pcs.log_stacking_height, and this is achieved by adding a single column of
        // zeroes as the last matrix of the commitment. We insert these "artificial" zeroes
        // into the evaluation claims.
        let zero_ext: Ext<SP1Field, SP1ExtensionField> =
            builder.constant(SP1ExtensionField::zero());
        for (insertion_point, num_added_columns) in
            insertion_points.iter().rev().zip(added_columns.iter().rev())
        {
            for _ in 0..*num_added_columns {
                column_claims.insert(*insertion_point, zero_ext);
            }
        }

        for (round_column_counts, round_row_counts, modified_commitment, original_commitment) in izip!(
            column_counts.iter(),
            proof.row_counts.iter(),
            commitments.iter(),
            original_commitments.iter()
        ) {
            let mut felts_vec: Vec<Felt<_>> =
                vec![builder.eval(SP1Field::from_canonical_usize(round_column_counts.len()))];
            for &count in round_row_counts {
                felts_vec.push(builder.eval(count));
            }

            for &count in round_column_counts {
                felts_vec.push(builder.eval(SP1Field::from_canonical_usize(count)));
            }
            let hash = SC::hash(builder, &felts_vec);
            let expected_commitment = SC::compress(builder, [*original_commitment, hash]);

            SC::assert_digest_eq(builder, expected_commitment, *modified_commitment);
        }

        // Pad the column claims to the next power of two.
        column_claims.resize(column_claims.len().next_power_of_two(), zero_ext);

        let column_mle = Mle::from(column_claims);
        let sumcheck_claim: Ext<SP1Field, SP1ExtensionField> =
            evaluate_mle_ext(builder, column_mle, z_col.clone())[0];

        builder.assert_ext_eq(sumcheck_claim, sumcheck_proof.claimed_sum);

        builder.cycle_tracker_v2_enter("jagged - verify sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, sumcheck_proof);
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("jagged - jagged-eval");
        let (jagged_eval, prefix_sum_felts) = self.jagged_evaluator.jagged_evaluation(
            builder,
            params,
            z_row,
            z_col,
            sumcheck_proof.point_and_eval.0.clone(),
            jagged_eval_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Check the prefix_sum_felts against the row counts.
        let repeated_flattened_row_counts: Vec<Felt<SP1Field>> = proof
            .row_counts
            .iter()
            .flatten()
            .zip_eq(column_counts.iter().flatten())
            .flat_map(|(row, col)| repeat_n(*row, *col))
            .collect();

        let mut acc: Felt<_> = builder.constant(SP1Field::zero());

        for (row_count, expected) in
            repeated_flattened_row_counts.iter().zip_eq(prefix_sum_felts.iter())
        {
            builder.assert_felt_eq(acc, *expected);
            acc = builder.eval(acc + *row_count)
        }
        let mut final_area = SymbolicFelt::zero();
        let two: Felt<_> = builder.constant(SP1Field::two());
        for bit in proof.params.col_prefix_sums.iter().last().unwrap().iter() {
            final_area = *bit + two * final_area;
        }
        builder.assert_felt_eq(acc, final_area);

        // Compute the expected evaluation of the dense trace polynomial.
        builder.assert_ext_eq(jagged_eval * *expected_eval, sumcheck_proof.point_and_eval.1);

        // Verify the evaluation proof.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        self.stacked_pcs_verifier.verify_untrusted_evaluation(
            builder,
            original_commitments,
            &evaluation_point,
            pcs_proof,
            SymbolicExt::from(*expected_eval),
            challenger,
        );
        prefix_sum_felts
    }
}

pub struct RecursiveMachineJaggedPcsVerifier<'a, SC: SP1FieldConfigVariable<C>, C: CircuitConfig> {
    pub jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<SC, C>,
    pub column_counts_by_round: Vec<Vec<usize>>,
}

impl<'a, SC: SP1FieldConfigVariable<C>, C: CircuitConfig>
    RecursiveMachineJaggedPcsVerifier<'a, SC, C>
{
    pub fn new(
        jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<SC, C>,
        column_counts_by_round: Vec<Vec<usize>>,
    ) -> Self {
        Self { jagged_pcs_verifier, column_counts_by_round }
    }

    pub fn verify_trusted_evaluations(
        &self,
        builder: &mut Builder<C>,
        commitments: &[SC::DigestVariable],
        point: Point<Ext<SP1Field, SP1ExtensionField>>,
        evaluation_claims: &[MleEval<Ext<SP1Field, SP1ExtensionField>>],
        proof: &JaggedPcsProofVariable<RecursiveBasefoldProof<C, SC>, SC::DigestVariable>,
        challenger: &mut SC::FriChallengerVariable,
    ) -> Vec<Felt<SP1Field>> {
        let insertion_points = self
            .column_counts_by_round
            .iter()
            .scan(0, |state, y| {
                *state += y.iter().sum::<usize>();
                Some(*state)
            })
            .collect::<Vec<_>>();

        self.jagged_pcs_verifier.verify_trusted_evaluations(
            builder,
            commitments,
            point,
            evaluation_claims,
            proof,
            &insertion_points,
            challenger,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, sync::Arc};

    use rand::{thread_rng, Rng};
    use slop_algebra::AbstractField;
    use slop_basefold::{BasefoldVerifier, FriConfig};
    use slop_challenger::{CanObserve, IopCtx};
    use slop_commit::Rounds;
    use slop_jagged::{JaggedPcsProof, JaggedPcsVerifier, JaggedProver};
    use slop_multilinear::{Evaluations, Mle, MleEval, PaddedMle, Point};
    use sp1_core_machine::utils::setup_logger;
    use sp1_hypercube::{
        inner_perm, prover::SP1InnerPcsProver, SP1InnerPcs, SP1PcsProof, SP1PcsProofInner,
    };
    use sp1_primitives::{SP1DiffusionMatrix, SP1ExtensionField, SP1Field, SP1GlobalContext};
    use sp1_recursion_compiler::circuit::{AsmBuilder, AsmCompiler, AsmConfig, CircuitV2Builder};
    use sp1_recursion_executor::Executor;

    use crate::{
        basefold::{
            stacked::RecursiveStackedPcsVerifier, tcs::RecursiveMerkleTreeTcs,
            RecursiveBasefoldVerifier,
        },
        challenger::{CanObserveVariable, DuplexChallengerVariable},
        jagged::{
            jagged_eval::RecursiveJaggedEvalSumcheckConfig,
            verifier::{RecursiveJaggedPcsVerifier, RecursiveMachineJaggedPcsVerifier},
        },
        witness::Witnessable,
    };

    type SC = SP1GlobalContext;
    type JC = SP1InnerPcs;
    type GC = SP1GlobalContext;
    type F = SP1Field;
    type EF = SP1ExtensionField;
    type C = AsmConfig;
    type Prover = JaggedProver<SP1GlobalContext, SP1PcsProofInner, SP1InnerPcsProver>;

    #[allow(clippy::type_complexity)]
    fn generate_jagged_proof(
        jagged_verifier: &JaggedPcsVerifier<GC, JC>,
        round_mles: Rounds<Vec<PaddedMle<F>>>,
        eval_point: Point<EF>,
    ) -> (
        JaggedPcsProof<GC, SP1PcsProof<GC>>,
        Rounds<<GC as IopCtx>::Digest>,
        Rounds<Evaluations<EF>>,
    ) {
        let jagged_prover = Prover::from_verifier(jagged_verifier);

        let mut challenger = jagged_verifier.challenger();

        let mut prover_data = Rounds::new();
        let mut commitments = Rounds::new();
        for round in round_mles.iter() {
            let (commit, data) = jagged_prover.commit_multilinears(round.clone()).ok().unwrap();
            challenger.observe(commit);
            let data_bytes = bincode::serialize(&data).unwrap();
            let data = bincode::deserialize(&data_bytes).unwrap();
            prover_data.push(data);
            commitments.push(commit);
        }

        let mut evaluation_claims = Rounds::new();
        for round in round_mles.iter() {
            let mut evals = Evaluations::default();
            for mle in round.iter() {
                let eval = mle.eval_at(&eval_point);
                evals.push(eval);
            }
            evaluation_claims.push(evals);
        }

        let proof = jagged_prover
            .prove_trusted_evaluations(
                eval_point.clone(),
                evaluation_claims.clone(),
                prover_data,
                &mut challenger,
            )
            .ok()
            .unwrap();

        (proof, commitments, evaluation_claims)
    }

    #[test]
    fn test_jagged_verifier() {
        setup_logger();

        let row_counts_rounds = vec![
            vec![
                1 << 13,
                1 << 8,
                1 << 11,
                1 << 7,
                1 << 16,
                1 << 14,
                1 << 20,
                1 << 7,
                1 << 9,
                1 << 11,
                1 << 8,
                1 << 7,
                1 << 14,
                1 << 10,
                1 << 14,
                1 << 8,
            ],
            vec![1 << 8],
        ];
        let column_counts_rounds = vec![
            vec![47, 41, 41, 58, 52, 109, 428, 50, 53, 93, 100, 83, 31, 68, 134, 80],
            vec![512],
        ];

        let num_rounds = row_counts_rounds.len();

        let log_stacking_height = 21;
        let max_log_row_count = 20;

        let row_counts = row_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();
        let column_counts = column_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();

        assert_eq!(row_counts.len(), column_counts.len());

        let mut rng = thread_rng();

        let round_mles = row_counts
            .iter()
            .zip(column_counts.iter())
            .map(|(row_counts, col_counts)| {
                row_counts
                    .iter()
                    .zip(col_counts.iter())
                    .map(|(num_rows, num_cols)| {
                        if *num_rows == 0 {
                            PaddedMle::zeros(*num_cols, max_log_row_count)
                        } else {
                            let mle = Mle::<F>::rand(&mut rng, *num_cols, num_rows.ilog(2));
                            PaddedMle::padded_with_zeros(Arc::new(mle), max_log_row_count)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Rounds<_>>();

        let jagged_verifier = JaggedPcsVerifier::<GC, JC>::new_from_basefold_params(
            FriConfig::default_fri_config(),
            log_stacking_height,
            max_log_row_count as usize,
            num_rounds,
        );

        let eval_point = (0..max_log_row_count).map(|_| rng.gen::<EF>()).collect::<Point<_>>();

        // Generate the jagged proof.
        let (proof, mut commitments, evaluation_claims) =
            generate_jagged_proof(&jagged_verifier, round_mles, eval_point.clone());

        let mut challenger = jagged_verifier.challenger();

        for commitment in commitments.iter() {
            // Ensure that the commitments are in the correct field.
            challenger.observe(*commitment);
        }

        let evaluation_claims = evaluation_claims
            .iter()
            .map(|round| {
                round.iter().flat_map(|evals| evals.iter().cloned()).collect::<MleEval<_>>()
            })
            .collect::<Vec<_>>();

        jagged_verifier
            .verify_trusted_evaluations(
                &commitments,
                eval_point.clone(),
                &evaluation_claims,
                &proof,
                &mut challenger,
            )
            .unwrap();

        // Define the verification circuit.
        let mut builder = AsmBuilder::default();
        builder.cycle_tracker_v2_enter("jagged - read input");
        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);
        let commitments_var = commitments.read(&mut builder);
        let eval_point_var = eval_point.read(&mut builder);
        let evaluation_claims_var = evaluation_claims.read(&mut builder);
        let proof_var = proof.read(&mut builder);
        builder.cycle_tracker_v2_exit();
        builder.cycle_tracker_v2_enter("jagged - observe commitments");
        for commitment_var in commitments_var.iter() {
            challenger_variable.observe_slice(&mut builder, *commitment_var);
        }
        builder.cycle_tracker_v2_exit();
        let verifier = BasefoldVerifier::<SC>::new(FriConfig::default_fri_config(), num_rounds);
        let recursive_verifier = RecursiveBasefoldVerifier::<C, SC> {
            fri_config: verifier.fri_config,
            tcs: RecursiveMerkleTreeTcs::<C, SC>(PhantomData),
        };
        let recursive_verifier =
            RecursiveStackedPcsVerifier::new(recursive_verifier, log_stacking_height);

        let recursive_jagged_verifier = RecursiveJaggedPcsVerifier::<SC, C> {
            stacked_pcs_verifier: recursive_verifier,
            max_log_row_count: max_log_row_count as usize,
            jagged_evaluator: RecursiveJaggedEvalSumcheckConfig::<SP1GlobalContext>(PhantomData),
        };

        let recursive_jagged_verifier = RecursiveMachineJaggedPcsVerifier::new(
            &recursive_jagged_verifier,
            vec![column_counts[0].clone(), column_counts[1].clone()],
        );

        builder.cycle_tracker_v2_enter("jagged-verifier");
        recursive_jagged_verifier.verify_trusted_evaluations(
            &mut builder,
            &commitments_var,
            eval_point_var,
            &evaluation_claims_var,
            &proof_var,
            &mut challenger_variable,
        );
        builder.cycle_tracker_v2_exit();

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();

        // Compile the verification circuit.
        let program = compiler.compile_inner(block).validate().unwrap();

        // Run the verification circuit with the proof artifacts.
        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&commitments, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&eval_point, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&evaluation_claims, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&proof, &mut witness_stream);
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(Arc::new(program.clone()), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().unwrap();

        // Run the verification circuit with the proof artifacts with an expected failure.
        let mut witness_stream = Vec::new();
        commitments.rounds[0][0] += F::one();
        Witnessable::<AsmConfig>::write(&commitments, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&eval_point, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&evaluation_claims, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&proof, &mut witness_stream);
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(Arc::new(program), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().expect_err("invalid proof should not be verified");
    }
}
