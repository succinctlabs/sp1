use serde::{Deserialize, Serialize};
use slop_algebra::{Field, TwoAdicField};
use slop_alloc::{CpuBackend, ToHost};
use slop_basefold::BasefoldProof;
use slop_basefold_prover::{
    BasefoldProver, BasefoldProverData, BasefoldProverError, CpuDftEncoder,
};
use slop_challenger::IopCtx;
use slop_commit::{Message, Rounds};
use slop_merkle_tree::ComputeTcsOpenings;
use slop_multilinear::{
    BatchPcsProver, Evaluations, Mle, MleEncoder, MleEval, MultilinearPcsProver, Point, ToMle,
};
use std::fmt::Debug;

use crate::{interleave_multilinears_with_fixed_rate, StackedBasefoldProof};

#[derive(Clone)]
pub struct StackedPcsProver<P: ComputeTcsOpenings<GC, CpuBackend>, GC: IopCtx<F: TwoAdicField>> {
    pub basefold_prover: BasefoldProver<GC, P>,
    pub log_stacking_height: u32,
    pub batch_size: usize,
    _marker: std::marker::PhantomData<GC>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackedBasefoldProverData<M, F, TcsProverData> {
    pcs_batch_data: BasefoldProverData<F, TcsProverData>,
    pub interleaved_mles: Message<M>,
}

impl<F: Field, PD> ToMle<F> for StackedBasefoldProverData<Mle<F>, F, PD> {
    fn interleaved_mles(&self) -> Message<Mle<F, CpuBackend>> {
        self.interleaved_mles.clone()
    }
}

impl<GC, P> StackedPcsProver<P, GC>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    P: ComputeTcsOpenings<GC, CpuBackend>,
{
    pub const fn new(
        basefold_prover: BasefoldProver<GC, P>,
        log_stacking_height: u32,
        batch_size: usize,
    ) -> Self {
        Self { basefold_prover, log_stacking_height, batch_size, _marker: std::marker::PhantomData }
    }

    pub fn round_batch_evaluations(
        &self,
        stacked_point: &Point<GC::EF>,
        prover_data: &StackedBasefoldProverData<Mle<GC::F>, GC::F, P::ProverData>,
    ) -> Evaluations<GC::EF> {
        prover_data
            .interleaved_mles
            .iter()
            .map(|mle| mle.eval_at(stacked_point))
            .collect::<Evaluations<_, _>>()
    }

    #[allow(clippy::type_complexity)]
    pub fn commit_multilinears(
        &self,
        multilinears: Message<Mle<GC::F>>,
    ) -> Result<
        (GC::Digest, StackedBasefoldProverData<Mle<GC::F>, GC::F, P::ProverData>, usize),
        BasefoldProverError<P::ProverError>,
    > {
        // To commit to the batch of padded Mles, the underlying PCS prover commits to the dense
        // representation of all of these Mles (i.e. a single "giga" Mle consisting of all the
        // entries of all the individual Mles),
        // padding the total area to the next multiple of the stacking height.
        let next_multiple = multilinears
            .iter()
            .map(|mle| mle.num_non_zero_entries() * mle.num_polynomials())
            .sum::<usize>()
            .next_multiple_of(1 << self.log_stacking_height)
            // Need to pad to at least one column.
            .max(1 << self.log_stacking_height);

        let num_added_vals = next_multiple
            - multilinears
                .iter()
                .map(|mle| mle.num_non_zero_entries() * mle.num_polynomials())
                .sum::<usize>();

        let interleaved_mles = interleave_multilinears_with_fixed_rate(
            self.batch_size,
            multilinears,
            self.log_stacking_height,
        );
        let (commit, pcs_batch_data) =
            self.basefold_prover.commit_mles(interleaved_mles.clone())?;
        let prover_data = StackedBasefoldProverData { pcs_batch_data, interleaved_mles };

        Ok((commit, prover_data, num_added_vals))
    }
}

/// A [`StackedPcsProver`] is a [`BatchPcsProver`]: a Basefold prover pinned to a fixed message
/// size (`num_encoding_variables = log_stacking_height`), mirroring the
/// [`BatchPcsVerifier`](slop_multilinear::BatchPcsVerifier) impl on
/// [`crate::StackedPcsVerifier`]. The opening protocol itself is plain prebatched Basefold;
/// the stacking height fixes how long the committed MLEs are allowed to be. `batch_size` and the
/// interleaving commit play no role on this path.
///
/// This is a temporary connector until stacked is refactored based on the new basefold API.
impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, P: ComputeTcsOpenings<GC, CpuBackend>>
    BatchPcsProver<GC> for StackedPcsProver<P, GC>
{
    type Proof = BasefoldProof<GC>;
    type ProverError = BasefoldProverError<P::ProverError>;
    type Encoder = CpuDftEncoder<GC::F>;
    type Commitment = GC::Digest;
    type ProverData = BasefoldProverData<GC::F, P::ProverData>;

    fn num_queries(&self) -> usize {
        self.basefold_prover.encoder.config().num_queries
    }

    fn num_encoding_variables(&self) -> u32 {
        self.log_stacking_height
    }

    fn encoder(&self) -> &Self::Encoder {
        &self.basefold_prover.encoder
    }

    fn commit_mles_with_log_blowup(
        &self,
        mles: Message<Mle<GC::F>>,
        log_blowup: usize,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        // Delegate to the basefold commit at the requested rate.
        self.basefold_prover.commit_mles_with_log_blowup(mles, log_blowup)
    }

    fn prove(
        &self,
        point: &Point<GC::EF>,
        eval: GC::EF,
        batched_polynomial: Mle<GC::EF>,
        batched_codeword: <Self::Encoder as MleEncoder<GC::F>>::Codeword,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> Result<Self::Proof, Self::ProverError> {
        self.basefold_prover.prove_from_prebatched_inputs(
            point.clone(),
            batched_polynomial,
            eval,
            batched_codeword,
            prover_data,
            challenger,
        )
    }
}

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, P: ComputeTcsOpenings<GC, CpuBackend>>
    MultilinearPcsProver<GC, StackedBasefoldProof<GC>> for StackedPcsProver<P, GC>
{
    type ProverData = StackedBasefoldProverData<Mle<GC::F>, GC::F, P::ProverData>;

    type ProverError = BasefoldProverError<P::ProverError>;

    fn commit_multilinear(
        &self,
        mles: Message<Mle<<GC as IopCtx>::F>>,
    ) -> Result<(<GC as IopCtx>::Digest, Self::ProverData, usize), Self::ProverError> {
        self.commit_multilinears(mles)
    }

    fn prove_trusted_evaluation(
        &self,
        eval_point: Point<<GC as IopCtx>::EF>,
        _evaluation_claim: <GC as IopCtx>::EF,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<StackedBasefoldProof<GC>, Self::ProverError> {
        let (_, stack_point) =
            eval_point.split_at(eval_point.dimension() - self.log_stacking_height as usize);
        let batch_evaluations: Rounds<_> = prover_data
            .iter()
            .map(|data| self.round_batch_evaluations(&stack_point, data))
            .collect();

        let mut host_batch_evaluations = Rounds::new();
        for round_evals in batch_evaluations.iter() {
            let mut host_round_evals = vec![];
            for eval in round_evals.iter() {
                let host_eval = eval.to_host().unwrap();
                host_round_evals.extend(host_eval);
            }
            let host_round_evals = Evaluations::new(vec![host_round_evals.into()]);
            host_batch_evaluations.push(host_round_evals);
        }
        let (pcs_prover_data, mle_rounds): (Rounds<_>, Rounds<_>) = prover_data
            .into_iter()
            .map(|data| (data.pcs_batch_data, data.interleaved_mles))
            .unzip();

        let (_, stack_point) =
            eval_point.split_at(eval_point.dimension() - self.log_stacking_height as usize);

        let batched_basefold_proof = self.basefold_prover.prove_untrusted_evaluations(
            stack_point,
            mle_rounds,
            batch_evaluations,
            pcs_prover_data,
            challenger,
        )?;

        let host_batch_evaluations = host_batch_evaluations
            .into_iter()
            .map(|round| round.into_iter().flatten().collect::<MleEval<_>>())
            .collect::<Rounds<_>>();

        Ok(StackedBasefoldProof {
            batched_basefold_proof,
            batch_evaluations: host_batch_evaluations,
        })
    }

    fn log_max_padding_amount(&self) -> u32 {
        self.log_stacking_height
    }
}
#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_basefold::{BasefoldVerifier, FriConfig};
    use slop_basefold_prover::BasefoldProver;
    use slop_challenger::CanObserve;
    use slop_merkle_tree::Poseidon2BabyBear16Prover;
    use slop_tensor::Tensor;

    use crate::StackedPcsVerifier;

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
        );
        let pcs_prover = Prover::new(&pcs_verifier);

        let verifier = StackedPcsVerifier::new(pcs_verifier, log_stacking_height);
        let prover = StackedPcsProver::new(pcs_prover, log_stacking_height, batch_size);

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

        let proof = prover
            .prove_trusted_evaluation(point.clone(), eval_claim, prover_data, &mut challenger)
            .unwrap();

        let mut challenger = GC::default_challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }
        verifier
            .verify_trusted_evaluation(
                &commitments,
                &round_areas,
                &point,
                &proof,
                eval_claim,
                &mut challenger,
            )
            .unwrap();
    }
}
