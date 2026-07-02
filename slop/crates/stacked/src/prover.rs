use serde::{Deserialize, Serialize};
use slop_algebra::Field;
use slop_alloc::{CpuBackend, ToHost};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_multilinear::{BatchPcsProver, Evaluations, Mle, MleEval, Point, ToMle};
use std::fmt::Debug;

use crate::{
    interleave_multilinears_with_fixed_rate, EqBatchedEvalClaim, EqBatchedProver, StackedEvalClaim,
    StackedProof,
};

#[derive(Clone)]
pub struct StackedPcsProver<P, GC> {
    pub batch_prover: EqBatchedProver<GC, P>,
    pub batch_size: usize,
    _marker: std::marker::PhantomData<GC>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackedProverData<M, InnerData> {
    pcs_batch_data: InnerData,
    pub interleaved_mles: Message<M>,
}

impl<M, InnerData> StackedProverData<M, InnerData> {
    /// Construct prover data from the inner base-PCS prover data and the interleaved MLEs that the
    /// stacked opening protocol re-derives evaluations from.
    ///
    /// External producers that perform their own stacking (e.g. the GPU prover, whose committed
    /// data already lives on-device) can pass an empty `interleaved_mles` when they never drive the
    /// CPU stacked opening path, which is the only consumer of that field.
    #[inline]
    pub const fn new(pcs_batch_data: InnerData, interleaved_mles: Message<M>) -> Self {
        Self { pcs_batch_data, interleaved_mles }
    }

    /// Construct prover data with no interleaved MLEs, for producers that do their own stacking and
    /// never drive the CPU stacked opening path (the only consumer of `interleaved_mles`) — e.g. the
    /// GPU prover, whose committed data already lives on-device.
    #[inline]
    pub fn from_batch_data(pcs_batch_data: InnerData) -> Self {
        Self { pcs_batch_data, interleaved_mles: Message::default() }
    }

    /// The inner base-PCS prover data captured at commit time.
    #[inline]
    pub const fn pcs_batch_data(&self) -> &InnerData {
        &self.pcs_batch_data
    }
}

impl<F: Field, PD> ToMle<F> for StackedProverData<Mle<F>, PD> {
    fn interleaved_mles(&self) -> Message<Mle<F, CpuBackend>> {
        self.interleaved_mles.clone()
    }
}

impl<GC, P> StackedPcsProver<P, GC>
where
    GC: IopCtx,
    P: BatchPcsProver<GC>,
{
    pub const fn new(batch_prover: EqBatchedProver<GC, P>, batch_size: usize) -> Self {
        Self { batch_prover, batch_size, _marker: std::marker::PhantomData }
    }

    pub fn round_batch_evaluations(
        &self,
        stacked_point: &Point<GC::EF>,
        prover_data: &StackedProverData<Mle<GC::F>, P::ProverData>,
    ) -> Evaluations<GC::EF> {
        prover_data
            .interleaved_mles
            .iter()
            .map(|mle| mle.eval_at(stacked_point))
            .collect::<Evaluations<_, _>>()
    }

    pub fn log_stacking_height(&self) -> u32 {
        self.batch_prover.prover.num_encoding_variables()
    }

    /// The per-round padded areas of the committed data (each a multiple of the stacking height),
    /// derived from the committed interleaved MLEs. Convenient for building the [`StackedEvalClaim`]
    /// `round_areas` on the prover side (the value the verifier derives independently).
    pub fn round_areas(
        &self,
        prover_data: &Rounds<StackedProverData<Mle<GC::F>, P::ProverData>>,
    ) -> Vec<usize> {
        prover_data
            .iter()
            .map(|data| {
                data.interleaved_mles
                    .iter()
                    .map(|mle| mle.num_polynomials() << mle.num_variables())
                    .sum::<usize>()
            })
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn commit_multilinears(
        &self,
        multilinears: Message<Mle<GC::F>>,
    ) -> Result<(GC::Digest, StackedProverData<Mle<GC::F>, P::ProverData>, usize), P::ProverError>
    {
        // To commit to the batch of padded Mles, the underlying PCS prover commits to the dense
        // representation of all of these Mles (i.e. a single "giga" Mle consisting of all the
        // entries of all the individual Mles),
        // padding the total area to the next multiple of the stacking height.
        let next_multiple = multilinears
            .iter()
            .map(|mle| mle.num_non_zero_entries() * mle.num_polynomials())
            .sum::<usize>()
            .next_multiple_of(1 << self.log_stacking_height())
            // Need to pad to at least one column.
            .max(1 << self.log_stacking_height());

        let num_added_vals = next_multiple
            - multilinears
                .iter()
                .map(|mle| mle.num_non_zero_entries() * mle.num_polynomials())
                .sum::<usize>();

        let interleaved_mles = interleave_multilinears_with_fixed_rate(
            self.batch_size,
            multilinears,
            self.log_stacking_height(),
        );
        let (commit, pcs_batch_data) =
            self.batch_prover.prover.commit_mles(interleaved_mles.clone())?;
        let prover_data = StackedProverData { pcs_batch_data, interleaved_mles };

        Ok((commit, prover_data, num_added_vals))
    }

    pub fn prove_untrusted_evaluation(
        &self,
        claim: &StackedEvalClaim<GC>,
        prover_data: Rounds<StackedProverData<Mle<GC::F>, P::ProverData>>,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<StackedProof<GC, P::Proof>, P::ProverError> {
        challenger.observe_ext_element(claim.evaluation);
        self.prove_trusted_evaluation(claim, prover_data, challenger)
    }

    pub fn prove_trusted_evaluation(
        &self,
        claim: &StackedEvalClaim<GC>,
        prover_data: Rounds<StackedProverData<Mle<GC::F>, P::ProverData>>,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<StackedProof<GC, P::Proof>, P::ProverError> {
        // The prover's opening logic uses only the evaluation point; `round_areas` and `evaluation`
        // live in the shared claim for symmetry with the verifier (the untrusted variant observes
        // `evaluation`, and the verifier cross-checks `round_areas`).
        let eval_point = &claim.point;
        let (_, stack_point) =
            eval_point.split_at(eval_point.dimension() - self.log_stacking_height() as usize);
        let batch_evaluations: Rounds<_> = prover_data
            .iter()
            .map(|data| self.round_batch_evaluations(&stack_point, data))
            .collect();

        // Flatten each round's per-table evals into a single host `MleEval` (one per commitment) —
        // this is the flattened form the batched claim and the proof both carry.
        let host_batch_evaluations: Rounds<MleEval<GC::EF>> = batch_evaluations
            .iter()
            .map(|round_evals| {
                round_evals.iter().flat_map(|eval| eval.to_host().unwrap()).collect::<MleEval<_>>()
            })
            .collect();

        let (pcs_prover_data, mle_rounds): (Rounds<_>, Rounds<_>) = prover_data
            .into_iter()
            .map(|data| (data.pcs_batch_data, data.interleaved_mles))
            .unzip();

        let batched_claim = EqBatchedEvalClaim {
            point: stack_point,
            evaluations: host_batch_evaluations.iter().cloned().collect(),
        };
        let inner_proof = self.batch_prover.prove_untrusted_evaluations(
            &batched_claim,
            mle_rounds,
            pcs_prover_data,
            challenger,
        )?;

        Ok(StackedProof { inner_proof, batch_evaluations: host_batch_evaluations })
    }
}
#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_basefold::{BasefoldVerifier, FriConfig, BATCH_GRINDING_BITS};
    use slop_basefold_prover::BasefoldProver;
    use slop_challenger::CanObserve;
    use slop_merkle_tree::Poseidon2BabyBear16Prover;
    use slop_tensor::Tensor;

    use crate::{EqBatchedVerifier, StackedEvalClaim, StackedPcsVerifier};

    use super::*;

    #[test]
    fn test_stacked_prover_with_fixed_rate_interleave() {
        let log_stacking_height = 10;
        let batch_size = 10;

        type GC = BabyBearDegree4Duplex;
        type Prover = BasefoldProver<GC, Poseidon2BabyBear16Prover>;
        type EF = BinomialExtensionField<BabyBear, 4>;

        let round_widths_and_log_heights = [vec![(1 << 10, 10), (1 << 4, 11), (496, 11)]];

        let total_data_length = round_widths_and_log_heights
            .iter()
            .map(|dims| dims.iter().map(|&(w, log_h)| w << log_h).sum::<usize>())
            .sum::<usize>();
        let total_number_of_variables = total_data_length.next_power_of_two().ilog2();
        assert_eq!(1 << total_number_of_variables, total_data_length);
        let round_areas = round_widths_and_log_heights
            .iter()
            .map(|dims| {
                dims.iter()
                    .map(|&(w, log_h)| w << log_h)
                    .sum::<usize>()
                    .next_multiple_of(1 << log_stacking_height)
            })
            .collect::<Vec<_>>();

        let mut rng = thread_rng();
        let round_mles = round_widths_and_log_heights
            .iter()
            .map(|dims| {
                dims.iter()
                    .map(|&(w, log_h)| Mle::<BabyBear>::rand(&mut rng, w, log_h))
                    .collect::<Message<_>>()
            })
            .collect::<Rounds<_>>();

        let pcs_verifier = BasefoldVerifier::<GC>::new(
            FriConfig::default_fri_config(),
            round_widths_and_log_heights.len(),
            log_stacking_height,
        );
        let pcs_prover = Prover::new(&pcs_verifier);

        let batch_pcs_verifier = EqBatchedVerifier::new(pcs_verifier, BATCH_GRINDING_BITS);
        let batch_pcs_prover = EqBatchedProver::new(pcs_prover, BATCH_GRINDING_BITS);

        let verifier = StackedPcsVerifier::new(batch_pcs_verifier);
        let prover = StackedPcsProver::new(batch_pcs_prover, batch_size);

        let mut challenger = GC::default_challenger();
        let mut commitments = vec![];
        let mut prover_data = Rounds::new();
        let mut batch_evaluations = Rounds::new();
        let point = Point::<EF>::rand(&mut rng, total_number_of_variables);

        let concat_mle: Vec<BabyBear> = round_mles
            .iter()
            .flat_map(|mles| mles.iter())
            .flat_map(|mle| mle.guts().transpose().as_slice().to_vec())
            .collect();

        let concat_mle =
            Mle::new(Tensor::from(concat_mle).reshape([1 << total_number_of_variables, 1]));

        let concat_eval_claim = concat_mle.eval_at(&point)[0];

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

        assert_eq!(concat_eval_claim, eval_claim);

        let claim = StackedEvalClaim {
            round_areas: round_areas.clone(),
            point: point.clone(),
            evaluation: eval_claim,
        };
        let proof = prover.prove_trusted_evaluation(&claim, prover_data, &mut challenger).unwrap();

        let mut challenger = GC::default_challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }
        verifier.verify_trusted_evaluation(&commitments, &claim, &proof, &mut challenger).unwrap();
    }
}
