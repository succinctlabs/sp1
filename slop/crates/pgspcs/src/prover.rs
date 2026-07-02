use slop_algebra::{AbstractField, TwoAdicField};
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldProof, BATCH_GRINDING_BITS};
use slop_basefold_prover::{BaseFoldConfigProverError, BasefoldProver, BasefoldProverData};
use slop_challenger::{GrindingChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_merkle_tree::ComputeTcsOpenings;
use slop_multilinear::{Mle, Point};
use slop_stacked::{EqBatchedEvalClaim, EqBatchedProof, EqBatchedProver};
use slop_sumcheck::{reduce_sumcheck_to_evaluation, PartialSumcheckProof};

use crate::{sparse_poly::SparsePolynomial, sumcheck_polynomials::SparsePCSSumcheckPoly};

/// The batched Basefold proof produced by the sparse PCS opening protocol.
pub type SparsePCSBasefoldProof<GC> =
    EqBatchedProof<BasefoldProof<GC>, <<GC as IopCtx>::Challenger as GrindingChallenger>::Witness>;

pub struct SparsePCSProver<GC: IopCtx, P: ComputeTcsOpenings<GC, CpuBackend>>
where
    GC::F: TwoAdicField,
{
    pub multilinear_prover: EqBatchedProver<GC, BasefoldProver<GC, P>>,
}

pub struct ProverData<GC: IopCtx, P: ComputeTcsOpenings<GC, CpuBackend>>
where
    GC::F: TwoAdicField,
{
    pub multilinear_prover_data: BasefoldProverData<GC::F, P::ProverData>,
    pub mles: Message<Mle<GC::F, CpuBackend>>,
}

pub struct Proof<EF, PCSProof> {
    pub evaluation_claims: Vec<EF>,
    pub sparse_sumcheck_proof: PartialSumcheckProof<EF>,
    pub pcs_proof: PCSProof,
}

impl<GC: IopCtx, P: ComputeTcsOpenings<GC, CpuBackend>> SparsePCSProver<GC, P>
where
    GC::F: TwoAdicField,
    GC::EF: TwoAdicField,
{
    pub fn new(prover: BasefoldProver<GC, P>) -> Self {
        Self { multilinear_prover: EqBatchedProver::new(prover, BATCH_GRINDING_BITS) }
    }

    #[allow(clippy::type_complexity)]
    pub fn commit_sparse_poly(
        &self,
        poly: &SparsePolynomial<GC::F>,
    ) -> Result<(GC::Digest, ProverData<GC, P>), BaseFoldConfigProverError<GC, P>> {
        // TODO: Implement batching
        // TODO: This is always done in a trusted setting, can something be optimized here?

        // Decompose the polynomial into the components to be committed
        let mut mles = poly.index_mles();
        mles.push(poly.val_mle());

        // Commit them as a MLE
        let mles: Message<Mle<_>> = mles.into();
        let (commitment, prover_data) = self.multilinear_prover.commit_mles(mles.clone())?;

        Ok((commitment, ProverData { multilinear_prover_data: prover_data, mles }))
    }

    pub fn prove_evaluation(
        &self,
        poly: &SparsePolynomial<GC::F>,
        eval_point: &Point<GC::EF>,
        prover_data: ProverData<GC, P>,
        challenger: &mut GC::Challenger,
    ) -> Result<Proof<GC::EF, SparsePCSBasefoldProof<GC>>, BaseFoldConfigProverError<GC, P>> {
        // Compute the evaluation claim
        let v = poly.eval_at(eval_point);

        // Run the sumcheck to reduce sum_b eq(eval_point, index(b)) * val(b) = v
        let sumcheck_poly = SparsePCSSumcheckPoly::<_, _>::new(eval_point, poly);
        let (pgspcs_proof, matrix_component_evals) = reduce_sumcheck_to_evaluation(
            vec![sumcheck_poly],
            challenger,
            vec![v],
            1,
            <GC::EF as AbstractField>::one(),
        );

        // Claim is now reduced to eq(eval_point, index(new_eval_point)) * val(new_eval_point)
        let new_eval_point = pgspcs_proof.point_and_eval.0.clone();
        let new_evaluation_claims = matrix_component_evals[0].clone();

        // Prove the evaluations (untrusted because we send them)
        let claim = EqBatchedEvalClaim {
            point: new_eval_point,
            // One committed round; the matrix component_evals are its evaluations, in order.
            evaluations: vec![new_evaluation_claims.clone().into()],
        };
        let pcs_proof = self.multilinear_prover.prove_untrusted_evaluations(
            &claim,
            // prover_data.mles = [index_1, ..., index_n, val]
            Rounds { rounds: vec![prover_data.mles] },
            Rounds { rounds: vec![prover_data.multilinear_prover_data] },
            challenger,
        )?;

        Ok(Proof {
            sparse_sumcheck_proof: pgspcs_proof,
            pcs_proof,
            evaluation_claims: new_evaluation_claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_basefold::{BasefoldVerifier, FriConfig};
    use slop_basefold_prover::BasefoldProver;
    use slop_merkle_tree::Poseidon2BabyBear16Prover;

    use crate::verifier::SparsePCSVerifier;

    use super::*;

    #[test]
    fn test_sparse_polynomial_prover() {
        type GC = BabyBearDegree4Duplex;
        type BackendProver = BasefoldProver<GC, Poseidon2BabyBear16Prover>;
        type BackendVerifier = BasefoldVerifier<GC>;
        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;

        let mut rng = thread_rng();

        let log_sparsity = 8;
        let num_variables = 16;
        let sparsity = 1 << log_sparsity;

        let poly = SparsePolynomial::<F>::new(
            (0..sparsity).map(|i| (i, F::from_canonical_usize(i))).collect(),
            num_variables,
        );
        let alpha = Point::new((0..num_variables).map(|_| rng.gen::<EF>()).collect());

        let basefold_verifier =
            BackendVerifier::new(FriConfig::default_fri_config(), 1, num_variables as u32);
        let basefold_prover = BackendProver::new(&basefold_verifier);

        let mut challenger = GC::default_challenger();

        let sparse_prover = SparsePCSProver::new(basefold_prover);
        let (commitment, prover_data) = sparse_prover.commit_sparse_poly(&poly).unwrap();

        let proof =
            sparse_prover.prove_evaluation(&poly, &alpha, prover_data, &mut challenger).unwrap();
        let evaluation_claim = poly.eval_at(&alpha);

        let mut challenger = GC::default_challenger();

        let sparse_verifier = SparsePCSVerifier::new(basefold_verifier);
        sparse_verifier
            .verify_trusted_evaluations(
                commitment,
                &alpha,
                evaluation_claim,
                &proof,
                &mut challenger,
            )
            .unwrap();
    }
}
