use slop_algebra::AbstractField;
use slop_alloc::CpuBackend;
use slop_basefold::BasefoldProof;
use slop_commit::Rounds;
use slop_jagged::{JaggedPcsProof, JaggedSumcheckEvalProof};
use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcsProof};
use slop_multilinear::MleEval;
use slop_tensor::Tensor;
use sp1_hypercube::{log2_ceil_usize, SP1PcsProof, SP1PcsProofInner, NUM_SP1_COMMITMENTS};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_executor::DIGEST_SIZE;

use crate::machine::{InnerChallenge, InnerVal};

use super::sumcheck::dummy_sumcheck_proof;

pub fn dummy_hash() -> [SP1Field; DIGEST_SIZE] {
    [SP1Field::zero(); DIGEST_SIZE]
}

pub fn dummy_query_proof(
    log_max_height: usize,
    log_blowup: usize,
    num_queries: usize,
) -> Vec<MerkleTreeOpeningAndProof<SP1GlobalContext>> {
    (0..log_max_height)
        .map(|i| {
            let openings = Tensor::<SP1Field, _>::zeros_in([num_queries, 4 * 2], CpuBackend);
            let proof = Tensor::<[SP1Field; DIGEST_SIZE], _>::zeros_in(
                [num_queries, log_max_height - i + log_blowup - 1],
                CpuBackend,
            );

            MerkleTreeOpeningAndProof {
                values: openings,
                proof: MerkleTreeTcsProof {
                    paths: proof,
                    merkle_root: dummy_hash(),
                    log_tensor_height: log_max_height - i + log_blowup - 1,
                    width: 4 * 2,
                },
            }
        })
        .collect::<Vec<_>>()
}

/// Make a dummy PCS proof for a given proof shape. Used to generate vkey information for fixed
/// proof shapes.
///
/// The parameter `batch_shapes` contains (width, height) data for each matrix in each batch.
pub fn dummy_pcs_proof(
    fri_queries: usize,
    max_log_row_count: usize,
    log_stacking_height_multiples: &[usize],
    log_stacking_height: usize,
    log_blowup: usize,
    column_counts_and_added_cols: Rounds<(Vec<usize>, usize)>,
) -> JaggedPcsProof<SP1GlobalContext, SP1PcsProofInner> {
    let (column_counts, added_cols): (Rounds<Vec<usize>>, Vec<usize>) =
        column_counts_and_added_cols.into_iter().unzip();
    let max_pcs_log_height = log_stacking_height;
    let dummy_component_polys = log_stacking_height_multiples.iter().map(|&x| {
        let proof = Tensor::<[SP1Field; DIGEST_SIZE], _>::zeros_in(
            [fri_queries, max_pcs_log_height + log_blowup],
            CpuBackend,
        );
        MerkleTreeOpeningAndProof::<SP1GlobalContext> {
            values: Tensor::<SP1Field, _>::zeros_in([fri_queries, x], CpuBackend),
            proof: MerkleTreeTcsProof {
                paths: proof,
                merkle_root: dummy_hash(),
                log_tensor_height: max_pcs_log_height + log_blowup,
                width: x,
            },
        }
    });
    let basefold_proof = BasefoldProof::<SP1GlobalContext> {
        univariate_messages: vec![[InnerChallenge::zero(); 2]; max_pcs_log_height],
        fri_commitments: vec![dummy_hash(); max_pcs_log_height],
        final_poly: InnerChallenge::zero(),
        pow_witness: InnerVal::zero(),
        component_polynomials_query_openings_and_proofs: dummy_component_polys.collect(),
        query_phase_openings_and_proofs: dummy_query_proof(
            max_pcs_log_height,
            log_blowup,
            fri_queries,
        ),
    };

    let batch_evaluations: Rounds<MleEval<InnerChallenge, CpuBackend>> = Rounds {
        rounds: log_stacking_height_multiples
            .iter()
            .map(|&x| vec![InnerChallenge::zero(); x].into())
            .collect(),
    };

    let stacked_proof = SP1PcsProof { basefold_proof, batch_evaluations };

    let total_trace = log2_ceil_usize(
        log_stacking_height_multiples.iter().sum::<usize>() * (1 << log_stacking_height),
    );
    let total_num_variables = total_trace;

    let partial_sumcheck_proof = dummy_sumcheck_proof(total_trace, 2);

    let eval_sumcheck_proof = dummy_sumcheck_proof(2 * (total_num_variables + 1), 2);

    let jagged_eval_proof = JaggedSumcheckEvalProof { partial_sumcheck_proof: eval_sumcheck_proof };

    let new_column_counts: Rounds<Vec<usize>> = column_counts
        .into_iter()
        .zip(added_cols.iter())
        .map(|(x, &added)| {
            // Commit paths always reserve at least one padding column.
            let added = added.max(1);
            x.into_iter().chain([added - 1, 1]).collect()
        })
        .collect();

    let row_counts_and_column_counts: Rounds<Vec<(usize, usize)>> = new_column_counts
        .clone()
        .into_iter()
        .map(|cc| cc.iter().map(|&c| (0, c)).collect())
        .collect();

    JaggedPcsProof {
        pcs_proof: stacked_proof,
        jagged_eval_proof,
        sumcheck_proof: partial_sumcheck_proof,
        merkle_tree_commitments: vec![dummy_hash(); NUM_SP1_COMMITMENTS].into_iter().collect(),
        row_counts_and_column_counts,
        expected_eval: InnerChallenge::zero(),
        max_log_row_count,
        log_m: total_trace,
    }
}

#[cfg(test)]
mod tests {

    use rand::{thread_rng, Rng};
    use slop_basefold::{BasefoldProof, FriConfig};
    use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
    use std::sync::Arc;

    use slop_challenger::CanObserve;
    use slop_commit::Rounds;
    use slop_jagged::{JaggedPcsVerifier, JaggedProver};
    use slop_multilinear::{Evaluations, Mle, PaddedMle, Point};

    use sp1_hypercube::{prover::SP1InnerPcsProver, SP1InnerPcs, SP1PcsProofInner};

    use crate::dummy::jagged::dummy_pcs_proof;

    #[test]
    fn test_dummy_jagged_proof() {
        let row_counts_rounds = vec![vec![1 << 9, 0, 1 << 9], vec![1 << 8]];
        let column_counts_rounds = vec![vec![128, 45, 32], vec![512]];

        let log_blowup = 1;
        let log_stacking_height = 10;
        let max_log_row_count = 9;

        type JC = SP1InnerPcs;
        type Prover = JaggedProver<SP1GlobalContext, SP1PcsProofInner, SP1InnerPcsProver>;
        type F = SP1Field;
        type EF = SP1ExtensionField;

        let row_counts = row_counts_rounds.clone().into_iter().collect::<Rounds<Vec<usize>>>();
        let column_counts =
            column_counts_rounds.clone().into_iter().collect::<Rounds<Vec<usize>>>();

        assert!(row_counts.len() == column_counts.len());

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

        let jagged_verifier = JaggedPcsVerifier::<_, JC>::new_from_basefold_params(
            FriConfig::default_fri_config(),
            log_stacking_height,
            max_log_row_count as usize,
            row_counts_rounds.len(),
        );

        let jagged_prover = Prover::from_verifier(&jagged_verifier);

        let eval_point = (0..max_log_row_count).map(|_| rng.gen::<EF>()).collect::<Point<_>>();

        // Begin the commit rounds
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

        let prep_multiple = row_counts_rounds[0]
            .iter()
            .zip(column_counts_rounds[0].iter())
            .map(|(row_count, col_count)| row_count * col_count)
            .sum::<usize>()
            .div_ceil(1 << log_stacking_height)
            .max(1);

        let main_multiple = row_counts_rounds[1]
            .iter()
            .zip(column_counts_rounds[1].iter())
            .map(|(row_count, col_count)| row_count * col_count)
            .sum::<usize>()
            .div_ceil(1 << log_stacking_height)
            .max(1);

        let preprocessed_padding_cols = (prep_multiple * (1 << log_stacking_height)
            - row_counts_rounds[0]
                .iter()
                .zip(column_counts_rounds[0].iter())
                .map(|(row_count, col_count)| row_count * col_count)
                .sum::<usize>())
        .div_ceil(1 << max_log_row_count)
        .max(1);

        let main_padding_cols = (main_multiple * (1 << log_stacking_height)
            - row_counts_rounds[1]
                .iter()
                .zip(column_counts_rounds[1].iter())
                .map(|(row_count, col_count)| row_count * col_count)
                .sum::<usize>())
        .div_ceil(1 << max_log_row_count)
        .max(1);

        // Magic constant 84 comes from the desired bits of security post grinding (for 16 bits of
        // grinding).
        let num_queries = 94;

        let dummy_proof = dummy_pcs_proof(
            num_queries,
            max_log_row_count as usize,
            &[prep_multiple, main_multiple],
            log_stacking_height as usize,
            log_blowup,
            column_counts
                .clone()
                .into_iter()
                .zip([preprocessed_padding_cols, main_padding_cols].iter())
                .map(|(cc, &ac)| (cc.clone(), ac))
                .collect(),
        );

        // Check the jagged sumcheck proof is the right shape.
        assert_eq!(
            dummy_proof.sumcheck_proof.univariate_polys.len(),
            proof.sumcheck_proof.univariate_polys.len()
        );
        assert_eq!(
            dummy_proof.sumcheck_proof.point_and_eval.0.dimension(),
            proof.sumcheck_proof.point_and_eval.0.dimension()
        );
        for (poly, dummy_poly) in proof
            .sumcheck_proof
            .univariate_polys
            .iter()
            .zip(dummy_proof.sumcheck_proof.univariate_polys.iter())
        {
            assert_eq!(poly.coefficients.len(), dummy_poly.coefficients.len());
        }

        // Check the jagged eval proof is the right shape.

        assert_eq!(
            dummy_proof.jagged_eval_proof.partial_sumcheck_proof.univariate_polys.len(),
            proof.jagged_eval_proof.partial_sumcheck_proof.univariate_polys.len()
        );
        assert_eq!(
            dummy_proof.jagged_eval_proof.partial_sumcheck_proof.point_and_eval.0.dimension(),
            proof.jagged_eval_proof.partial_sumcheck_proof.point_and_eval.0.dimension()
        );
        for (poly, dummy_poly) in proof
            .jagged_eval_proof
            .partial_sumcheck_proof
            .univariate_polys
            .iter()
            .zip(dummy_proof.jagged_eval_proof.partial_sumcheck_proof.univariate_polys.iter())
        {
            assert_eq!(poly.coefficients.len(), dummy_poly.coefficients.len());
        }

        // Check the stacked proof is the right shape.
        assert_eq!(
            dummy_proof.pcs_proof.batch_evaluations.rounds.len(),
            proof.pcs_proof.batch_evaluations.rounds.len()
        );
        for (round, dummy_round) in proof
            .pcs_proof
            .batch_evaluations
            .rounds
            .iter()
            .zip(dummy_proof.pcs_proof.batch_evaluations.rounds.iter())
        {
            assert_eq!(round.num_polynomials(), dummy_round.num_polynomials());
        }
        // Check that the BaseFold proof is the right shape.
        let BasefoldProof {
            univariate_messages: dummy_univariate_messages,
            fri_commitments: dummy_fri_commitments,
            component_polynomials_query_openings_and_proofs:
                dummy_component_polynomials_query_openings,
            query_phase_openings_and_proofs: dummy_query_phase_openings,
            ..
        } = dummy_proof.pcs_proof.basefold_proof;

        let BasefoldProof {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings_and_proofs,
            query_phase_openings_and_proofs,
            ..
        } = proof.pcs_proof.basefold_proof;

        assert_eq!(dummy_univariate_messages.len(), univariate_messages.len());
        assert_eq!(dummy_fri_commitments.len(), fri_commitments.len());
        assert_eq!(
            dummy_component_polynomials_query_openings.len(),
            component_polynomials_query_openings_and_proofs.len()
        );
        assert_eq!(dummy_query_phase_openings.len(), query_phase_openings_and_proofs.len());

        for (dummy_opening, opening) in
            dummy_query_phase_openings.iter().zip(query_phase_openings_and_proofs.iter())
        {
            assert_eq!(dummy_opening.values.shape(), opening.values.shape());
            assert_eq!(dummy_opening.proof.paths.shape(), opening.proof.paths.shape());
        }

        for (dummy_opening, opening) in dummy_component_polynomials_query_openings
            .iter()
            .zip(component_polynomials_query_openings_and_proofs.iter())
        {
            assert_eq!(dummy_opening.values.shape(), opening.values.shape());
            assert_eq!(dummy_opening.proof.paths.shape(), opening.proof.paths.shape());
        }
    }
}
