use super::RecursiveMultilinearPcsVerifier;
use crate::{challenger::FieldChallengerVariable, sumcheck::evaluate_mle_ext};
use slop_commit::Rounds;
use slop_multilinear::{Mle, MleEval, Point};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, SymbolicExt},
};

#[derive(Clone)]
pub struct RecursiveStackedPcsVerifier<P> {
    pub recursive_pcs_verifier: P,
    pub log_stacking_height: u32,
}

pub struct RecursiveStackedPcsProof<PcsProof, F, EF> {
    pub batch_evaluations: Rounds<MleEval<Ext<F, EF>>>,
    pub pcs_proof: PcsProof,
}

impl<P: RecursiveMultilinearPcsVerifier> RecursiveStackedPcsVerifier<P> {
    pub const fn new(recursive_pcs_verifier: P, log_stacking_height: u32) -> Self {
        Self { recursive_pcs_verifier, log_stacking_height }
    }

    pub fn verify_untrusted_evaluation(
        &self,
        builder: &mut Builder<P::Circuit>,
        commitments: &[P::Commitment],
        point: &Point<Ext<SP1Field, SP1ExtensionField>>,
        proof: &RecursiveStackedPcsProof<P::Proof, SP1Field, SP1ExtensionField>,
        evaluation_claim: SymbolicExt<SP1Field, SP1ExtensionField>,
        challenger: &mut P::Challenger,
    ) {
        let claim_ext: Ext<_, _> = builder.eval(evaluation_claim);
        challenger.observe_ext_element(builder, claim_ext);
        let (batch_point, stack_point) =
            point.split_at(point.dimension() - self.log_stacking_height as usize);
        let batch_evaluations =
            proof.batch_evaluations.iter().flatten().cloned().collect::<Mle<_>>();

        builder.cycle_tracker_v2_enter("rizz - evaluate_mle_ext");
        let expected_evaluation = evaluate_mle_ext(builder, batch_evaluations, batch_point)[0];
        builder.assert_ext_eq(claim_ext, expected_evaluation);
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("rizz - verify_untrusted_evaluations");
        self.recursive_pcs_verifier.verify_untrusted_evaluations(
            builder,
            commitments,
            stack_point,
            &proof.batch_evaluations,
            &proof.pcs_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_challenger::IopCtx;
    use slop_commit::Message;
    use sp1_core_machine::utils::setup_logger;
    use sp1_recursion_compiler::{circuit::AsmConfig, config::InnerConfig};
    use std::{collections::VecDeque, marker::PhantomData, sync::Arc};

    use slop_algebra::extension::BinomialExtensionField;
    use sp1_primitives::{SP1DiffusionMatrix, SP1GlobalContext};

    use crate::{
        basefold::{tcs::RecursiveMerkleTreeTcs, RecursiveBasefoldVerifier},
        challenger::DuplexChallengerVariable,
        witness::Witnessable,
    };

    use super::*;

    use slop_basefold::{BasefoldVerifier, FriConfig, BATCH_GRINDING_BITS};
    use slop_basefold_prover::BasefoldProver;
    use slop_challenger::CanObserve;

    use slop_commit::Rounds;

    use crate::challenger::CanObserveVariable;
    use slop_multilinear::Mle;
    use slop_stacked::{EqBatchedProver, StackedEvalClaim, StackedPcsProver};
    use sp1_hypercube::{inner_perm, prover::SP1MerkleTreeProver};
    use sp1_recursion_compiler::circuit::{AsmBuilder, AsmCompiler};
    use sp1_recursion_executor::Executor;

    use sp1_primitives::SP1Field;
    type F = SP1Field;

    fn test_round_widths_and_log_heights(
        round_widths_and_log_heights: &[Vec<(usize, u32)>],
        log_stacking_height: u32,
        batch_size: usize,
    ) {
        type C = InnerConfig;
        type SC = SP1GlobalContext;
        type Prover = BasefoldProver<SP1GlobalContext, SP1MerkleTreeProver>;
        type EF = BinomialExtensionField<SP1Field, 4>;
        let total_data_length = round_widths_and_log_heights
            .iter()
            .map(|dims| dims.iter().map(|&(w, log_h)| w << log_h).sum::<usize>())
            .sum::<usize>();
        let total_number_of_variables = total_data_length.next_power_of_two().ilog2();
        assert_eq!(1 << total_number_of_variables, total_data_length);

        let mut rng = thread_rng();
        let round_mles = round_widths_and_log_heights
            .iter()
            .map(|dims| {
                dims.iter()
                    .map(|&(w, log_h)| Mle::<SP1Field>::rand(&mut rng, w, log_h))
                    .collect::<Message<_>>()
            })
            .collect::<Rounds<_>>();

        let pcs_verifier = BasefoldVerifier::<SC>::new(
            FriConfig::default_fri_config(),
            round_widths_and_log_heights.len(),
            log_stacking_height,
        );
        let pcs_prover = Prover::new(&pcs_verifier);

        let prover = StackedPcsProver::new(
            EqBatchedProver::new(pcs_prover, BATCH_GRINDING_BITS),
            batch_size,
        );

        let mut challenger = SC::default_challenger();
        let mut commitments = vec![];
        let mut prover_data = Rounds::new();
        let mut batch_evaluations = Rounds::new();
        let point = Point::<EF>::rand(&mut rng, total_number_of_variables);

        let (batch_point, stack_point) =
            point.split_at(point.dimension() - log_stacking_height as usize);
        for mles in round_mles.iter() {
            let (commitment, data, _) = prover.commit_multilinears(mles.clone()).unwrap();
            challenger.observe(commitment);
            commitments.push(commitment);
            let evaluations = prover.round_batch_evaluations(&stack_point, &data);
            prover_data.push(data);
            batch_evaluations.push(evaluations);
        }

        // Interpolate the batch evaluations as a multilinear polynomial.
        let batch_evaluations_mle =
            batch_evaluations.iter().flatten().flatten().cloned().collect::<Mle<_>>();
        // Verify that the climed evaluations matched the interpolated evaluations.
        let eval_claim = batch_evaluations_mle.eval_at(&batch_point)[0];

        let stacked_claim = StackedEvalClaim {
            round_areas: prover.round_areas(&prover_data),
            point: point.clone(),
            evaluation: eval_claim,
        };
        let proof = prover
            .prove_untrusted_evaluation(&stacked_claim, prover_data, &mut challenger)
            .unwrap();

        let mut builder = AsmBuilder::default();
        let mut witness_stream = Vec::new();
        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);

        Witnessable::<AsmConfig>::write(&commitments, &mut witness_stream);
        let commitments = commitments.read(&mut builder);

        for commitment in commitments.iter() {
            challenger_variable.observe(&mut builder, *commitment);
        }

        Witnessable::<AsmConfig>::write(&point, &mut witness_stream);
        let point = point.read(&mut builder);

        Witnessable::<AsmConfig>::write(&proof, &mut witness_stream);
        let proof = proof.read(&mut builder);

        Witnessable::<AsmConfig>::write(&eval_claim, &mut witness_stream);
        let eval_claim = eval_claim.read(&mut builder);

        let verifier = BasefoldVerifier::<SC>::new(
            FriConfig::default_fri_config(),
            round_widths_and_log_heights.len(),
            log_stacking_height,
        );
        let recursive_verifier = RecursiveBasefoldVerifier::<C, SC> {
            fri_config: verifier.fri_config,
            tcs: RecursiveMerkleTreeTcs::<C, SC>(PhantomData),
        };
        let recursive_verifier =
            RecursiveStackedPcsVerifier::new(recursive_verifier, log_stacking_height);

        recursive_verifier.verify_untrusted_evaluation(
            &mut builder,
            &commitments,
            &point,
            &proof,
            eval_claim.into(),
            &mut challenger_variable,
        );

        let mut buf = VecDeque::<u8>::new();
        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.debug_stdout = Box::new(&mut buf);
        executor.run().unwrap();
    }

    #[test]
    fn test_stacked_pcs_proof() {
        setup_logger();
        let round_widths_and_log_heights: Vec<(usize, u32)> =
            vec![(1 << 10, 10), (1 << 4, 11), (496, 11)];
        test_round_widths_and_log_heights(&[round_widths_and_log_heights], 10, 10);
    }

    #[test]
    #[ignore = "should be invoked specifically"]
    fn test_stacked_pcs_proof_core_shard() {
        setup_logger();
        let round_widths_and_log_heights = [vec![
            (30, 21),
            (44, 21),
            (45, 21),
            (18, 20),
            (400, 18),
            (25, 20),
            (100, 20),
            (40, 19),
            (22, 19),
        ]];
        test_round_widths_and_log_heights(&round_widths_and_log_heights, 21, 1);
        test_round_widths_and_log_heights(&round_widths_and_log_heights, 21, 5);
    }

    #[test]
    #[ignore = "should be invoked specifically"]
    fn test_stacked_pcs_proof_precompile_shard() {
        setup_logger();
        let round_widths_and_log_heights = [vec![(4000, 16), (400, 19), (20, 20), (21, 21)]];
        test_round_widths_and_log_heights(&round_widths_and_log_heights, 21, 1);
        test_round_widths_and_log_heights(&round_widths_and_log_heights, 21, 5);
    }
}
