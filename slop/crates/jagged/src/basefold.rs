use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_baby_bear::baby_bear_poseidon2::BabyBearDegree4Duplex;
use slop_basefold::{BasefoldVerifier, FriConfig, BATCH_GRINDING_BITS};
use slop_basefold_prover::BasefoldProver;
use slop_bn254::BNGC;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::ComputeTcsOpenings;
use slop_stacked::{EqBatchedProver, StackedPcsProver, StackedPcsVerifier};

use crate::{DefaultJaggedProver, JaggedAssistProver, JaggedPcsVerifier, JaggedProver};

pub type BabyBearStackedBasefoldVerifier =
    StackedPcsVerifier<BabyBearDegree4Duplex, BasefoldVerifier<BabyBearDegree4Duplex>>;

pub type KoalaBearStackedBasefoldVerifier =
    StackedPcsVerifier<KoalaBearDegree4Duplex, BasefoldVerifier<KoalaBearDegree4Duplex>>;

pub type Bn254StackedBasefoldVerifier<F, EF> =
    StackedPcsVerifier<BNGC<F, EF>, BasefoldVerifier<BNGC<F, EF>>>;

impl<GC> JaggedPcsVerifier<GC, BasefoldVerifier<GC>>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
{
    pub fn new_from_basefold_params(
        fri_config: FriConfig<GC::F>,
        log_stacking_height: u32,
        max_log_row_count: usize,
        expected_number_of_commits: usize,
    ) -> Self {
        let basefold_verifer = BasefoldVerifier::<GC>::new(
            fri_config,
            expected_number_of_commits,
            log_stacking_height,
        );
        let stacked_pcs_verifier =
            StackedPcsVerifier::new_from_inner(basefold_verifer, BATCH_GRINDING_BITS);
        Self::new(stacked_pcs_verifier, max_log_row_count)
    }
}

impl<GC, MerkleProver> JaggedProver<GC, BasefoldProver<GC, MerkleProver>>
where
    MerkleProver: ComputeTcsOpenings<GC, CpuBackend> + Default,
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
{
    pub fn from_basefold_components(
        verifier: &JaggedPcsVerifier<GC, BasefoldVerifier<GC>>,
        interleave_batch_size: usize,
    ) -> Self {
        let pcs_prover = BasefoldProver::new(&verifier.stacked_pcs_verifier.inner_verifier.inner);
        let batched_prover = EqBatchedProver::new(pcs_prover, BATCH_GRINDING_BITS);
        let stacked_pcs_prover = StackedPcsProver::new(batched_prover, interleave_batch_size);

        Self::new(
            verifier.max_log_row_count,
            stacked_pcs_prover,
            JaggedAssistProver::<GC>::default(),
        )
    }
}

const DEFAULT_INTERLEAVE_BATCH_SIZE: usize = 32;

impl<MerkleProver, GC> DefaultJaggedProver<GC, BasefoldVerifier<GC>>
    for BasefoldProver<GC, MerkleProver>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MerkleProver: ComputeTcsOpenings<GC, CpuBackend> + Default,
{
    fn prover_from_verifier(
        verifier: &JaggedPcsVerifier<GC, BasefoldVerifier<GC>>,
    ) -> JaggedProver<GC, Self> {
        JaggedProver::from_basefold_components(verifier, DEFAULT_INTERLEAVE_BATCH_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rand::{thread_rng, Rng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::BabyBear;
    use slop_basefold::BasefoldProof;
    use slop_challenger::CanObserve;
    use slop_commit::Rounds;
    use slop_koala_bear::KoalaBear;
    use slop_merkle_tree::{BnProver, Poseidon2BabyBear16Prover, Poseidon2KoalaBear16Prover};
    use slop_multilinear::{BatchPcsProver, Evaluations, Mle, MleEval, PaddedMle, Point};

    use super::*;

    #[test]
    fn test_baby_bear_jagged_basefold() {
        test_jagged_basefold::<BabyBearDegree4Duplex, BasefoldProver<_, Poseidon2BabyBear16Prover>>(
        );
    }

    #[test]
    fn test_koala_bear_jagged_basefold() {
        test_jagged_basefold::<KoalaBearDegree4Duplex, BasefoldProver<_, Poseidon2KoalaBear16Prover>>(
        );
    }

    #[test]
    fn test_bn254_jagged_basefold() {
        test_jagged_basefold::<
            BNGC<BabyBear, BinomialExtensionField<BabyBear, 4>>,
            BasefoldProver<_, BnProver<BabyBear, BinomialExtensionField<BabyBear, 4>>>,
        >();
    }

    #[test]
    fn test_bn254_jagged_kb_basefold() {
        test_jagged_basefold::<
            BNGC<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
            BasefoldProver<_, BnProver<KoalaBear, BinomialExtensionField<KoalaBear, 4>>>,
        >();
    }

    fn test_jagged_basefold<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        PcsProver: BatchPcsProver<GC, Proof = BasefoldProof<GC>>
            + DefaultJaggedProver<GC, BasefoldVerifier<GC>>,
    >()
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let row_counts_rounds = vec![vec![1 << 10, 0, 1 << 10], vec![1 << 8]];
        let column_counts_rounds = vec![vec![128, 45, 32], vec![512]];
        let num_rounds = row_counts_rounds.len();

        let log_stacking_height = 11;
        let max_log_row_count = 10;

        let row_counts = row_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();
        let column_counts = column_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();

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
                            let mle = Mle::<GC::F>::rand(&mut rng, *num_cols, num_rows.ilog(2));
                            PaddedMle::padded_with_zeros(Arc::new(mle), max_log_row_count)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Rounds<_>>();

        let jagged_verifier =
            JaggedPcsVerifier::<GC, BasefoldVerifier<GC>>::new_from_basefold_params(
                FriConfig::default_fri_config(),
                log_stacking_height,
                max_log_row_count as usize,
                num_rounds,
            );

        let jagged_prover = JaggedProver::<GC, PcsProver>::from_verifier(&jagged_verifier);

        let eval_point = (0..max_log_row_count).map(|_| rng.gen::<GC::EF>()).collect::<Point<_>>();

        // Begin the commit rounds
        let mut challenger = jagged_verifier.challenger();

        let mut prover_data = Rounds::new();
        let mut commitments = Rounds::new();
        for round in round_mles.iter() {
            let (commit, data) = jagged_prover.commit_multilinears(round.clone()).ok().unwrap();
            challenger.observe(commit);
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

        let mut challenger = jagged_verifier.challenger();
        for commitment in commitments.iter() {
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
                eval_point,
                &evaluation_claims,
                &proof,
                &mut challenger,
            )
            .unwrap();
    }
}
