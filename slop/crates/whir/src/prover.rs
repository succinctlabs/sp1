use std::{
    convert::Infallible,
    iter::{self, once},
    sync::Arc,
};

use crate::{
    config::WhirProofShape,
    verifier::{map_to_pow, ParsedCommitment, ProofOfWork, SumcheckPoly, WhirProof},
    Verifier,
};
use derive_where::derive_where;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::{
    CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx,
    VariableLengthChallenger,
};
use slop_commit::{Message, Rounds};
use slop_dft::{p3::Radix2DitParallel, Dft};
use slop_jagged::{DefaultJaggedProver, JaggedEvalSumcheckProver, JaggedProver};
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::{
    ComputeTcsOpenings, FieldMerkleTreeProver, MerkleTreeOpeningAndProof,
    Poseidon2KoalaBear16Prover, TensorCsProver,
};
use slop_multilinear::{
    monomial_basis_evals_blocking, partial_lagrange_blocking, Mle, MultilinearPcsProver, PaddedMle,
    Point, ToMle,
};
use slop_tensor::Tensor;
use slop_utils::reverse_bits_len;

fn batch_dft<D, F, EF>(dft: &D, data: Tensor<EF>, log_blowup: usize) -> Tensor<EF>
where
    F: Field,
    EF: ExtensionField<F>,
    D: Dft<F>,
{
    assert_eq!(data.sizes().len(), 2, "Expected a 2D tensor");

    let base_tensor = data.flatten_to_base();

    let base_tensor =
        dft.dft(&base_tensor, log_blowup, slop_dft::DftOrdering::BitReversed, 0).unwrap();
    base_tensor.into_extension()
}

fn interleave<F: Clone>(left: Tensor<F>, right: Tensor<F>) -> Tensor<F> {
    assert_eq!(left.sizes().len(), 2);
    assert_eq!(right.sizes().len(), 2);
    assert_eq!(left.sizes()[0], right.sizes()[0]);
    let width_1 = left.sizes()[1];
    let width_2 = right.sizes()[1];
    let height = left.sizes()[0];

    left.into_buffer()
        .chunks_exact(width_1)
        .zip(right.into_buffer().chunks_exact(width_2))
        .flat_map(|(l, r)| l.iter().chain(r.iter()).cloned().collect::<Vec<_>>())
        .collect::<Tensor<_, CpuBackend>>()
        .reshape([height, width_1 + width_2])
}

pub fn interleave_chain<F: Clone>(iter: impl Iterator<Item = Tensor<F>>) -> Tensor<F> {
    let mut iter = iter.peekable();
    let first = iter.next().unwrap();
    iter.fold(first, |acc, x| interleave(acc, x))
}

#[cfg(test)]
pub(crate) fn concat_transpose<F: Field>(
    iter: impl Iterator<Item = Arc<Mle<F>>> + Clone,
) -> Mle<F> {
    let total_len = iter.clone().map(|m| m.guts().as_slice().len()).sum::<usize>();
    let mut result = Vec::with_capacity(total_len);
    for mle in iter {
        result.extend(mle.guts().transpose().as_slice().iter().copied());
    }

    Mle::new(Tensor::from(result).reshape([total_len, 1]))
}

pub struct Prover<GC, MerkleProver, D>
where
    GC: IopCtx,
    MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
{
    dft: D,
    merkle_prover: MerkleProver,
    config: WhirProofShape<GC::F>,
    _marker: std::marker::PhantomData<GC>,
}

pub struct WitnessData<GC, MerkleProver>
where
    GC: IopCtx,
    MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
{
    parsed_commitment: ParsedCommitment<GC>,
    polynomial: Mle<GC::F>,
    committed_data: Rounds<Tensor<GC::F>>,
    commitment_data: Rounds<MerkleProver::ProverData>,
}

#[derive_where(Debug; GC: IopCtx, MerkleProver: TensorCsProver<GC, CpuBackend>, MerkleProver::ProverData: std::fmt::Debug)]
pub struct WhirProverData<GC, MerkleProver>
where
    GC: IopCtx,
    MerkleProver: TensorCsProver<GC, CpuBackend>,
{
    commitment_data: MerkleProver::ProverData,
    committed_data: Tensor<GC::F>,
    polynomial: Mle<GC::F>,
    precommitment_poly: Mle<GC::F>,
    commitment: GC::Digest,
}

impl<GC: IopCtx, MerkleProver: TensorCsProver<GC, CpuBackend>> Clone
    for WhirProverData<GC, MerkleProver>
where
    MerkleProver::ProverData: Clone,
{
    fn clone(&self) -> Self {
        Self {
            commitment_data: self.commitment_data.clone(),
            committed_data: self.committed_data.clone(),
            polynomial: self.polynomial.clone(),
            precommitment_poly: self.precommitment_poly.clone(),
            commitment: self.commitment,
        }
    }
}

impl<GC: IopCtx, MerkleProver: TensorCsProver<GC, CpuBackend>> ToMle<GC::F>
    for WhirProverData<GC, MerkleProver>
where
    GC: IopCtx,
    MerkleProver: TensorCsProver<GC, CpuBackend>,
{
    fn interleaved_mles(&self) -> Message<Mle<GC::F, CpuBackend>> {
        Message::from(self.precommitment_poly.clone())
    }
}

impl<GC, MerkleProver, D> Prover<GC, MerkleProver, D>
where
    GC: IopCtx,
    D: Dft<GC::F>,
    MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
{
    pub fn new(dft: D, merkle_prover: MerkleProver, config: WhirProofShape<GC::F>) -> Self {
        Self { dft, merkle_prover, config, _marker: std::marker::PhantomData }
    }

    pub fn parse_commitment_data(
        &self,
        challenger: &mut GC::Challenger,
        config: &WhirProofShape<GC::F>,
        rounds: Rounds<WhirProverData<GC, MerkleProver>>,
    ) -> WitnessData<GC, MerkleProver> {
        let num_variables = rounds
            .iter()
            .map(|r| r.polynomial.guts().as_slice().len())
            .sum::<usize>()
            .next_power_of_two()
            .ilog2();

        let num_non_zero_entries: usize =
            rounds.iter().map(|r| r.polynomial.guts().as_slice().len()).sum();
        let ood_points: Vec<Point<GC::EF>> = (0..config.starting_ood_samples)
            .map(|_| {
                (0..num_variables)
                    .map(|_| challenger.sample_ext_element())
                    .collect::<Vec<GC::EF>>()
                    .into()
            })
            .collect();

        let num_to_add = (1 << num_variables) - num_non_zero_entries;

        let concatenated_polynomial = if num_to_add != 0 {
            let result = interleave_chain(
                rounds
                    .iter()
                    .map(|r| {
                        let num_entries = r.polynomial.guts().total_len();
                        assert!(
                            num_entries.is_multiple_of(1 << config.starting_interleaved_log_height)
                        );
                        r.polynomial.guts().clone().reshape([
                            1 << config.starting_interleaved_log_height,
                            num_entries / (1 << config.starting_interleaved_log_height),
                        ])
                    })
                    .chain(once(Tensor::from(vec![GC::F::zero(); num_to_add]).reshape([
                        1 << config.starting_interleaved_log_height,
                        num_to_add / (1 << config.starting_interleaved_log_height),
                    ]))),
            )
            .into_buffer()
            .to_vec();

            assert_eq!(result.len(), 1 << num_variables);
            for i in 0..(num_to_add >> config.starting_interleaved_log_height) {
                for j in 0..(1 << config.starting_interleaved_log_height) {
                    assert_eq!(
                        result[(num_non_zero_entries >> config.starting_interleaved_log_height)
                            + i
                            + (j << (num_variables
                                - config.starting_interleaved_log_height as u32))],
                        GC::F::zero()
                    );
                }
            }

            result
        } else {
            interleave_chain(rounds.iter().map(|r| {
                let num_entries = r.polynomial.guts().total_len();
                r.polynomial.guts().clone().reshape([
                    1 << config.starting_interleaved_log_height,
                    num_entries / (1 << config.starting_interleaved_log_height),
                ])
            }))
            .into_buffer()
            .to_vec()
        };

        // concatenated_polynomial.resize(1 << num_variables, GC::F::zero());

        let concatenated_polynomial =
            Mle::new(Tensor::from(concatenated_polynomial).reshape([1 << num_variables, 1]));

        let ood_answers: Vec<GC::EF> = ood_points
            .iter()
            .map(|point| concatenated_polynomial.blocking_monomial_basis_eval_at(point)[0])
            .collect();

        // The length of this vector is determined by the agreed-upon "WHIR config", so its length
        // does not need to be observed.
        challenger.observe_constant_length_extension_slice(&ood_answers);

        let parsed_commitment = ParsedCommitment {
            commitment: rounds.iter().map(|r| r.commitment).collect(),
            ood_points,
            ood_answers,
        };

        let (committed_data, commitment_data) =
            rounds.into_iter().map(|r| (r.committed_data, r.commitment_data)).unzip();

        WitnessData {
            parsed_commitment,
            polynomial: concatenated_polynomial,
            committed_data,
            commitment_data,
        }
    }

    pub fn prove(
        &self,
        query_vector: Mle<GC::EF>,
        witness_data: Rounds<WhirProverData<GC, MerkleProver>>,
        claim: GC::EF,
        challenger: &mut GC::Challenger,
        config: &WhirProofShape<GC::F>,
    ) -> WhirProof<GC> {
        let n_rounds = config.round_parameters.len();

        let witness_data = self.parse_commitment_data(challenger, config, witness_data);

        let claim_batching_randomness: GC::EF = challenger.sample_ext_element();
        let claimed_sum: GC::EF = claim_batching_randomness
            .powers()
            .zip(std::iter::once(&claim).chain(&witness_data.parsed_commitment.ood_answers))
            .map(|(r, &v)| r * v)
            .sum();
        let mut parsed_commitments = Vec::with_capacity(n_rounds);

        parsed_commitments.push(witness_data.parsed_commitment.clone());

        let num_variables = query_vector.num_variables() as usize;

        let mut sumcheck_prover = SumcheckProver::<GC, GC::F>::new(
            witness_data.polynomial.clone(),
            query_vector,
            witness_data.parsed_commitment.ood_points.clone(),
            claim_batching_randomness,
        );

        let (initial_sumcheck_polynomials, mut folding_randomness, mut claimed_sum) =
            sumcheck_prover.compute_sumcheck_polynomials(
                claimed_sum,
                num_variables - config.starting_interleaved_log_height,
                &config.starting_folding_pow_bits,
                challenger,
            );

        let mut generator = config.domain_generator;
        let mut merkle_proofs = Vec::with_capacity(n_rounds);
        let mut query_proof_of_works = Vec::with_capacity(n_rounds);
        let mut sumcheck_polynomials = Vec::with_capacity(n_rounds);

        let mut prev_domain_log_size = config.starting_domain_log_size;
        let mut prev_folding_factor = num_variables - config.starting_interleaved_log_height;
        let (mut prev_prover_data, mut prev_committed_data) = (
            witness_data.commitment_data,
            witness_data.committed_data.into_iter().map(Arc::new).collect::<Rounds<_>>(),
        );

        for round_index in 0..n_rounds {
            let round_params = &config.round_parameters[round_index];

            let num_nonzero_entries = match &sumcheck_prover.f_vec {
                KOrEfMle::K(mle) => mle.inner().as_ref().unwrap().num_non_zero_entries(),
                KOrEfMle::EF(mle) => mle.inner().as_ref().unwrap().num_non_zero_entries(),
            };
            let inner_evals = match &sumcheck_prover.f_vec {
                KOrEfMle::K(_) => unreachable!("Should be of type EF after first sumcheck"),
                KOrEfMle::EF(mle) => mle.inner().as_ref().unwrap().guts().clone().reshape([
                    num_nonzero_entries.div_ceil(1 << round_params.folding_factor),
                    1 << round_params.folding_factor,
                ]),
            };

            let encoding =
                batch_dft::<_, GC::F, GC::EF>(&self.dft, inner_evals, round_params.log_inv_rate);

            let encoding_base = encoding.flatten_to_base();

            let (commitment, prover_data) = self
                .merkle_prover
                .commit_tensors(Message::<Tensor<GC::F>>::from(vec![encoding_base.clone()]))
                .unwrap();

            // Observe the commitment
            challenger.observe(commitment);

            let f_vec = match sumcheck_prover.f_vec {
                KOrEfMle::K(_) => unreachable!("Should be of type EF after first sumcheck"),
                KOrEfMle::EF(ref mle) => mle,
            };

            // Squeeze the ood points
            let ood_points: Vec<Point<GC::EF>> = (0..round_params.ood_samples)
                .map(|_| {
                    (0..f_vec.num_variables())
                        .map(|_| challenger.sample_ext_element())
                        .collect::<Vec<GC::EF>>()
                        .into()
                })
                .collect();

            let ood_answers: Vec<GC::EF> = ood_points
                .iter()
                .map(|point| {
                    f_vec.inner().as_ref().unwrap().blocking_monomial_basis_eval_at(point)[0]
                })
                .collect();

            challenger.observe_constant_length_extension_slice(&ood_answers);

            parsed_commitments.push(ParsedCommitment::<GC> {
                commitment: vec![commitment].into_iter().collect(),
                ood_points: ood_points.clone(),
                ood_answers: ood_answers.clone(),
            });

            query_proof_of_works
                .push(challenger.grind(round_params.queries_pow_bits.ceil() as usize));

            let id_query_indices = (0..round_params.num_queries)
                .map(|_| challenger.sample_bits(prev_domain_log_size))
                .collect::<Vec<_>>();
            let id_query_values: Vec<GC::F> = id_query_indices
                .iter()
                .map(|val| reverse_bits_len(*val, prev_domain_log_size))
                .map(|pos| generator.exp_u64(pos as u64))
                .collect();

            let claim_batching_randomness: GC::EF = challenger.sample_ext_element();

            let merkle_openings: Vec<_> = prev_committed_data
                .into_iter()
                .map(|data| {
                    self.merkle_prover.compute_openings_at_indices(
                        Message::<Tensor<_>>::from(vec![data]),
                        &id_query_indices,
                    )
                })
                .collect();

            let num_openings: usize = merkle_openings.iter().map(|o| o.sizes()[1]).sum();

            // assert!(num_openings <= 1 << prev_folding_factor);

            let merkle_proof: Vec<_> = prev_prover_data
                .into_iter()
                .map(|data| {
                    self.merkle_prover.prove_openings_at_indices(data, &id_query_indices).unwrap()
                })
                .collect();
            let merkle_proof = merkle_proof
                .into_iter()
                .zip(merkle_openings.into_iter())
                .map(|(proof, opening)| MerkleTreeOpeningAndProof { values: opening, proof })
                .collect::<Vec<_>>();
            let merkle_read_values: Vec<Mle<GC::EF>> = if round_index != 0 {
                assert!(merkle_proof.len() == 1);
                merkle_proof[0]
                    .values
                    .clone()
                    .into_buffer()
                    .into_extension::<GC::EF>()
                    .to_vec()
                    .chunks_exact(1 << prev_folding_factor)
                    .map(|v| Mle::new(v.to_vec().into()))
                    .collect()
            } else {
                interleave_chain(merkle_proof.iter().map(|p| p.values.clone()))
                    .into_buffer()
                    .to_vec()
                    .into_iter()
                    .map(GC::EF::from)
                    .collect::<Vec<_>>()
                    .chunks_exact(num_openings)
                    .map(|v| Mle::new(v.to_vec().into()))
                    .collect::<Vec<_>>()
            };
            merkle_proofs.push(merkle_proof);

            let stir_values: Vec<GC::EF> = merkle_read_values
                .iter()
                .map(|coeffs| coeffs.blocking_eval_at(&folding_randomness.clone().into())[0])
                .collect();

            // Update the claimed sum
            claimed_sum = claim_batching_randomness
                .powers()
                .zip(iter::once(&claimed_sum).chain(&ood_answers).chain(&stir_values))
                .map(|(r, &v)| v * r)
                .sum();

            let new_eq_polys = [
                ood_points.clone(),
                id_query_values
                    .into_iter()
                    .map(|point| map_to_pow(point, f_vec.num_variables() as usize).to_extension())
                    .collect(),
            ]
            .concat();
            sumcheck_prover.add_equality_polynomials(new_eq_polys, claim_batching_randomness);

            let (round_sumcheck_polynomials, round_folding_randomness, round_claimed_sum) =
                sumcheck_prover.compute_sumcheck_polynomials(
                    claimed_sum,
                    round_params.folding_factor,
                    &round_params.pow_bits,
                    challenger,
                );

            folding_randomness = round_folding_randomness;
            claimed_sum = round_claimed_sum;

            sumcheck_polynomials.push(round_sumcheck_polynomials);

            // Update
            generator = generator.square();
            prev_folding_factor = round_params.folding_factor;
            prev_domain_log_size = round_params.evaluation_domain_log_size;
            (prev_prover_data, prev_committed_data) = (
                vec![prover_data].into_iter().collect(),
                vec![Arc::new(encoding_base)].into_iter().collect(),
            );
        }

        let f_vec = match &sumcheck_prover.f_vec {
            KOrEfMle::K(_) => unreachable!("Should be of type EF after first sumcheck"),
            KOrEfMle::EF(mle) => mle,
        };

        let final_polynomial =
            f_vec.inner().as_ref().unwrap().guts().clone().into_buffer().to_vec();
        challenger.observe_constant_length_extension_slice(&final_polynomial);

        let final_pow = challenger.grind(config.final_pow_bits.ceil() as usize);

        let final_id_indices = (0..config.final_queries)
            .map(|_| challenger.sample_bits(prev_domain_log_size))
            .collect::<Vec<_>>();

        let final_merkle_openings = self.merkle_prover.compute_openings_at_indices(
            Message::<Tensor<GC::F>>::from(prev_committed_data.into_iter().collect::<Vec<_>>()),
            &final_id_indices,
        );

        assert!(prev_prover_data.len() == 1);
        let final_merkle_proof = self
            .merkle_prover
            .prove_openings_at_indices(prev_prover_data[0].clone(), &final_id_indices)
            .unwrap();
        let final_merkle_proof =
            MerkleTreeOpeningAndProof { values: final_merkle_openings, proof: final_merkle_proof };

        let (final_sumcheck_polynomials, _, _) = sumcheck_prover.compute_sumcheck_polynomials(
            claimed_sum,
            config.final_poly_log_degree,
            &config.final_folding_pow_bits,
            challenger,
        );

        WhirProof {
            config: config.clone(),
            initial_sumcheck_polynomials,
            commitments: parsed_commitments,
            merkle_proofs: merkle_proofs
                .into_iter()
                .map(|rounds| rounds.into_iter().collect())
                .collect(),
            query_proofs_of_work: query_proof_of_works,
            sumcheck_polynomials,
            final_polynomial,
            final_merkle_opening_and_proof: final_merkle_proof,
            final_sumcheck_polynomials,
            final_pow,
        }
    }
}

impl<GC, MerkleProver, D> MultilinearPcsProver<GC, WhirProof<GC>> for Prover<GC, MerkleProver, D>
where
    GC: IopCtx,
    D: Dft<GC::F>,
    MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
{
    type ProverData = WhirProverData<GC, MerkleProver>;

    type ProverError = Infallible;

    fn commit_multilinear(
        &self,
        mles: Message<Mle<<GC as IopCtx>::F>>,
    ) -> Result<(<GC as IopCtx>::Digest, Self::ProverData, usize), Self::ProverError> {
        let len: usize = mles.iter().map(|mle| mle.guts().as_slice().len()).sum();
        let added_zeroes =
            len.next_multiple_of(1 << self.config.starting_interleaved_log_height) - len;
        let tensor: Tensor<GC::F, CpuBackend> = mles
            .iter()
            .flat_map(|mle| mle.guts().transpose().as_slice().to_vec())
            .chain(std::iter::repeat_n(GC::F::zero(), added_zeroes))
            .collect::<Tensor<_>>()
            .reshape([len + added_zeroes, 1]);
        let concatenated_mles = Mle::new(tensor);

        let starting_interleaved_height = self.config.starting_interleaved_log_height;
        let num_non_zero_entries = concatenated_mles.num_non_zero_entries();

        let inner_evals = concatenated_mles
            .guts()
            .clone()
            .reshape([
                num_non_zero_entries / (1 << starting_interleaved_height),
                1 << starting_interleaved_height,
            ])
            .transpose();

        let encoding = batch_dft(&self.dft, inner_evals.clone(), self.config.starting_log_inv_rate);

        let (commitment, prover_data) =
            self.merkle_prover.commit_tensors(encoding.clone().into()).unwrap();

        let witness = WhirProverData {
            commitment_data: prover_data,
            committed_data: encoding,
            polynomial: Mle::new(inner_evals.clone().reshape([num_non_zero_entries, 1])),
            precommitment_poly: concatenated_mles,
            commitment,
        };
        Ok((witness.commitment, witness, added_zeroes))
    }

    fn prove_trusted_evaluation(
        &self,
        eval_point: Point<<GC as IopCtx>::EF>,
        evaluation_claim: <GC as IopCtx>::EF,
        prover_data: slop_commit::Rounds<Self::ProverData>,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<WhirProof<GC>, Self::ProverError> {
        let (folding_point, stacked_point) = eval_point
            .split_at(eval_point.dimension() - self.config.starting_interleaved_log_height);
        let eval_point = stacked_point
            .iter()
            .copied()
            .chain(folding_point.iter().copied())
            .collect::<Point<_>>();
        Ok(self.prove(
            Mle::new(partial_lagrange_blocking(&eval_point)),
            prover_data,
            evaluation_claim,
            challenger,
            &self.config,
        ))
    }

    fn log_max_padding_amount(&self) -> u32 {
        self.config.starting_interleaved_log_height as u32
    }
}

impl DefaultJaggedProver<KoalaBearDegree4Duplex, Verifier<KoalaBearDegree4Duplex>>
    for Prover<KoalaBearDegree4Duplex, Poseidon2KoalaBear16Prover, Radix2DitParallel>
{
    fn prover_from_verifier(
        verifier: &slop_jagged::JaggedPcsVerifier<
            KoalaBearDegree4Duplex,
            Verifier<KoalaBearDegree4Duplex>,
        >,
    ) -> slop_jagged::JaggedProver<KoalaBearDegree4Duplex, WhirProof<KoalaBearDegree4Duplex>, Self>
    {
        let merkle_prover = FieldMerkleTreeProver::default();
        let prover = Prover::<_, _, _>::new(
            Radix2DitParallel,
            merkle_prover,
            verifier.pcs_verifier.config.clone(),
        );

        JaggedProver::new(verifier.max_log_row_count, prover, JaggedEvalSumcheckProver::default())
    }
}

enum KOrEfMle<K, EF> {
    K(PaddedMle<K>),
    EF(PaddedMle<EF>),
}

impl<K, EF> KOrEfMle<K, EF>
where
    K: Field,
    EF: ExtensionField<K>,
{
    pub fn inner_prod(&self, other: Mle<EF>) -> (EF, EF) {
        match self {
            KOrEfMle::K(mle) => mle
                .inner()
                .as_ref()
                .unwrap()
                .guts()
                .as_slice()
                .par_iter()
                .zip_eq(other.guts().as_slice().par_iter())
                .map(|(m, z)| (*m, *z))
                .chunks(2)
                .map(|chunk| {
                    let (e0, e1) = (chunk[0], chunk[1]);
                    let f0 = e0.0;
                    let f1 = e1.0;
                    let v0 = e0.1;
                    let v1 = e1.1;

                    (v0 * f0, (v1 - v0) * (f1 - f0))
                })
                .reduce(
                    || (EF::zero(), EF::zero()),
                    |(acc0, acc2), (v0, v2)| (acc0 + v0, acc2 + v2),
                ),
            KOrEfMle::EF(mle) => mle
                .inner()
                .as_ref()
                .unwrap()
                .guts()
                .as_slice()
                .par_iter()
                .zip_eq(other.guts().as_slice().par_iter())
                .map(|(m, z)| (*m, *z))
                .chunks(2)
                .map(|chunk| {
                    let (e0, e1) = (chunk[0], chunk[1]);
                    let f0 = e0.0;
                    let f1 = e1.0;
                    let v0 = e0.1;
                    let v1 = e1.1;

                    (v0 * f0, (v1 - v0) * (f1 - f0))
                })
                .reduce(
                    || (EF::zero(), EF::zero()),
                    |(acc0, acc1), (v0, v1)| (acc0 + v0, acc1 + v1),
                ),
        }
    }
    pub fn fix_last_variable(&self, value: EF) -> Self {
        match self {
            KOrEfMle::K(mle) => KOrEfMle::EF(mle.fix_last_variable(value)),
            KOrEfMle::EF(mle) => KOrEfMle::EF(mle.fix_last_variable(value)),
        }
    }
}

pub struct SumcheckProver<GC, K>
where
    GC: IopCtx,
    K: Field,
    GC::EF: ExtensionField<K>,
{
    f_vec: KOrEfMle<K, GC::EF>,
    eq_vec: Mle<GC::EF>,
}

impl<GC, K> SumcheckProver<GC, K>
where
    GC: IopCtx,
    K: Field,
    GC::EF: ExtensionField<K>,
{
    fn new(
        f_vec: Mle<K>,
        query_vector: Mle<GC::EF>,
        eq_points: Vec<Point<GC::EF>>,
        combination_randomness: GC::EF,
    ) -> Self {
        // assert!(!eq_points.is_empty());
        let mut acc = combination_randomness;
        let mut eq_vec = query_vector.into_guts().into_buffer().to_vec();
        for mle in eq_points.iter().map(monomial_basis_evals_blocking) {
            Mle::new(mle)
                .hypercube_iter()
                .enumerate()
                .for_each(|(i, val)| eq_vec[i] += acc * val[0]);
            acc *= combination_randomness;
        }

        let f_vec = PaddedMle::padded_with_zeros(Arc::new(f_vec), eq_points[0].dimension() as u32);

        SumcheckProver { f_vec: KOrEfMle::K(f_vec), eq_vec: eq_vec.into() }
    }

    fn add_equality_polynomials(
        &mut self,
        eq_points: Vec<Point<GC::EF>>,
        combination_randomness: GC::EF,
    ) {
        let mut eq_vec = self.eq_vec.guts().clone().into_buffer().to_vec();
        let mut acc = combination_randomness;
        for mle in eq_points.iter().map(monomial_basis_evals_blocking) {
            Mle::new(mle)
                .hypercube_iter()
                .enumerate()
                .for_each(|(i, val)| eq_vec[i] += acc * val[0]);
            acc *= combination_randomness;
        }
        self.eq_vec = eq_vec.into();
    }

    #[allow(clippy::type_complexity)]
    fn compute_sumcheck_polynomials(
        &mut self,
        mut claimed_sum: GC::EF,
        num_rounds: usize,
        pow_bits: &[f64],
        challenger: &mut GC::Challenger,
    ) -> (Vec<(SumcheckPoly<GC::EF>, ProofOfWork<GC>)>, Vec<GC::EF>, GC::EF) {
        let mut res = Vec::with_capacity(num_rounds);
        let mut folding_randomness = Vec::with_capacity(num_rounds);

        for round_pow_bits in &pow_bits[..num_rounds] {
            // Constant and quadratic term
            let (c0, c2) = self.f_vec.inner_prod(self.eq_vec.clone());

            let c1 = claimed_sum - c0.double() - c2;

            let sumcheck_poly = SumcheckPoly([c0, c1, c2]);

            challenger.observe_constant_length_extension_slice(&sumcheck_poly.0);
            let pow = challenger.grind(round_pow_bits.ceil() as usize);
            let folding_randomness_single: GC::EF = challenger.sample_ext_element();
            claimed_sum = sumcheck_poly.evaluate_at_point(folding_randomness_single);
            res.push((sumcheck_poly, pow));
            folding_randomness.push(folding_randomness_single);

            self.f_vec = self.f_vec.fix_last_variable(folding_randomness_single);
            self.eq_vec = self.eq_vec.fix_last_variable(folding_randomness_single);
        }
        folding_randomness.reverse();
        let num_added_zeroes = match self.f_vec {
            KOrEfMle::K(_) => {
                unimplemented!("Should be of type EF after first sumcheck")
            }
            KOrEfMle::EF(ref mle) => {
                self.eq_vec.guts().as_slice().len()
                    - mle.inner().as_ref().unwrap().num_non_zero_entries()
            }
        };
        match &mut self.f_vec {
            KOrEfMle::K(_) => unreachable!("Should be of type EF after first sumcheck"),
            KOrEfMle::EF(ref mut mle) => {
                let mut new_buffer = mle.inner().as_ref().unwrap().guts().clone().into_buffer();
                new_buffer.extend_from_slice(&vec![GC::EF::zero(); num_added_zeroes]);
                let num_variables = mle.num_variables();
                self.f_vec = KOrEfMle::EF(PaddedMle::padded_with_zeros(
                    Arc::new(Mle::new(Tensor::from(new_buffer).reshape([1 << num_variables, 1]))),
                    num_variables,
                ));
            }
        }
        (res, folding_randomness, claimed_sum)
    }
}

#[cfg(test)]
mod tests {

    use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng, SeedableRng};
    use slop_algebra::{extension::BinomialExtensionField, TwoAdicField, UnivariatePolynomial};
    use slop_baby_bear::BabyBear;
    use slop_commit::Rounds;
    use slop_dft::p3::Radix2DitParallel;
    use slop_jagged::{JaggedEvalSumcheckProver, JaggedPcsVerifier, JaggedProver};
    use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
    use slop_matrix::{bitrev::BitReversableMatrix, dense::RowMajorMatrix, Matrix};
    use slop_merkle_tree::{
        FieldMerkleTreeProver, MerkleTreeTcs, Poseidon2BabyBear16Prover, Poseidon2KoalaBear16Prover,
    };
    use slop_multilinear::{Evaluations, MultilinearPcsVerifier, PaddedMle};
    use slop_utils::setup_logger;

    use super::*;
    use crate::{
        config::{RoundConfig, WhirProofShape},
        verifier::Verifier,
    };

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn big_beautiful_whir_config<F: TwoAdicField>() -> WhirProofShape<F> {
        let folding_factor = 4;
        WhirProofShape::<F> {
            domain_generator: F::two_adic_generator(21),
            starting_ood_samples: 2,
            starting_log_inv_rate: 1,
            starting_interleaved_log_height: 20,
            starting_domain_log_size: 21,
            starting_folding_pow_bits: vec![0.; 8],
            round_parameters: vec![
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 20,
                    queries_pow_bits: 16.0,
                    pow_bits: vec![0.0; folding_factor],
                    num_queries: 84,
                    ood_samples: 2,
                    log_inv_rate: 4,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 19,
                    queries_pow_bits: 16.0,
                    pow_bits: vec![0.0; folding_factor],
                    num_queries: 21,
                    ood_samples: 2,
                    log_inv_rate: 7,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 18,
                    queries_pow_bits: 16.0,
                    pow_bits: vec![0.0; folding_factor],
                    num_queries: 12,
                    ood_samples: 2,
                    log_inv_rate: 10,
                },
            ],
            final_poly_log_degree: 8,
            final_queries: 9,
            final_pow_bits: 16.0,
            final_folding_pow_bits: vec![0.0; 8],
        }
    }

    #[test]
    fn whir_folding() {
        const FOLDING_FACTOR: usize = 4;
        let blowup_factor = 2;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let dft = Radix2DitParallel;

        let polynomial: Mle<F> = Mle::rand(&mut rng, 1, 8);

        let num_variables = polynomial.num_variables() as usize;
        let inner_evals = polynomial
            .guts()
            .clone()
            .reshape([(1 << num_variables) / (1 << FOLDING_FACTOR), 1 << FOLDING_FACTOR]);

        let encoding = batch_dft::<_, F, F>(&dft, inner_evals, blowup_factor);

        let [r1, r2, r3, r4]: [EF; FOLDING_FACTOR] = rng.gen();

        let folded_poly = polynomial
            .fix_last_variable(r1)
            .fix_last_variable(r2)
            .fix_last_variable(r3)
            .fix_last_variable(r4);

        let encoding_of_fold =
            batch_dft::<_, F, EF>(&dft, folded_poly.guts().clone(), blowup_factor);

        let encoding_of_fold_vec = encoding_of_fold.into_buffer().to_vec();

        let columns: Vec<_> = encoding
            .clone()
            .into_buffer()
            .to_vec()
            .chunks_exact(1 << FOLDING_FACTOR)
            .map(|v| Mle::new(v.to_vec().into()))
            .collect();

        assert_eq!(columns.len(), 1 << (num_variables + blowup_factor - FOLDING_FACTOR));

        let uv_coeff = folded_poly.guts().clone().into_buffer().to_vec();
        let mle_evals = folded_poly.clone();
        let uv = UnivariatePolynomial::new(uv_coeff);

        let gen = EF::two_adic_generator(num_variables - FOLDING_FACTOR + blowup_factor);
        let powers: Vec<_> =
            gen.powers().take(1 << (num_variables + blowup_factor - FOLDING_FACTOR)).collect();
        let bit_reversed_powers =
            RowMajorMatrix::new(powers, 1).bit_reverse_rows().to_row_major_matrix().values;

        for ((col, enc), val) in
            columns.into_iter().zip(encoding_of_fold_vec).zip(bit_reversed_powers)
        {
            // We fixed `r1` as last variable first, so it should be the last coordinate of the
            // point. This assertion tests that the encoding of the folded polynomial
            // matches the folding onf the encoded polynomial.
            assert_eq!(enc, col.blocking_eval_at(&vec![r4, r3, r2, r1].into())[0]);

            // This assertion checks that the encoding of the folded polynomial is the bit-reversed
            // RS-encoding of the univariate polynomial whose coefficients are the same as the
            // elements of the folded polynomial (we always represent multilinears in
            // the evaluation basis).
            assert_eq!(enc, uv.eval_at_point(val));
            let num_variables = mle_evals.num_variables() as usize;
            let point = (0..num_variables)
                .map(|i| val.exp_power_of_2(num_variables - 1 - i))
                .collect::<Point<_>>();

            // This assertion checks the compatibility between the multilinear representation of the
            // folded polynomial and its encoding: namely if we form the point
            // (val^{2^{num_variables-1}}, ..., val^2, val) and evaluate `mle_evals` in
            // the monomial basis representation, that should be the same
            // thing as computing the DFT value at the current location.
            assert_eq!(enc, mle_evals.blocking_monomial_basis_eval_at(&point)[0]);
        }
    }

    type GC = KoalaBearDegree4Duplex;

    #[test]
    fn whir_test_sumcheck() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let mut challenger_prover = GC::default_challenger();

        let num_variables: usize = 4;
        let polynomial: Mle<F> = Mle::rand(&mut rng, 1, num_variables as u32);
        let query_vector: Mle<EF> = Mle::rand(&mut rng, 1, num_variables as u32);

        let mut sumcheck_prover = SumcheckProver::<GC, KoalaBear>::new(
            polynomial.clone(),
            query_vector.clone(),
            vec![vec![EF::zero(); num_variables].into(); 1],
            EF::zero(),
        );

        let claim: EF = polynomial
            .hypercube_iter()
            .zip(query_vector.hypercube_iter())
            .map(|(a, b)| b[0] * a[0])
            .sum();

        let (_, folding_randmness, claimed_sum) = sumcheck_prover.compute_sumcheck_polynomials(
            claim,
            num_variables,
            &vec![0.; num_variables],
            &mut challenger_prover,
        );

        assert_eq!(
            query_vector.blocking_eval_at(&folding_randmness.clone().into())[0]
                * polynomial.blocking_eval_at(&folding_randmness.clone().into())[0],
            claimed_sum
        );
    }

    #[test]
    fn whir_test_sumcheck_with_eq_modification() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let mut challenger_prover = GC::default_challenger();

        let num_variables: usize = 8;
        let polynomial: Mle<F> = Mle::rand(&mut rng, 1, num_variables as u32);
        let query_vector: Mle<EF> = Mle::rand(&mut rng, 1, num_variables as u32);

        let z_initial: Point<EF> = (0..num_variables).map(|_| rng.gen()).collect();

        let mut sumcheck_prover = SumcheckProver::<GC, F>::new(
            polynomial.clone(),
            query_vector.clone(),
            vec![z_initial.clone()],
            EF::one(),
        );

        let claim: EF = polynomial
            .hypercube_iter()
            .zip(query_vector.hypercube_iter())
            .map(|(a, b)| b[0] * a[0])
            .sum::<EF>()
            + polynomial.blocking_monomial_basis_eval_at(&z_initial)[0];

        let (_, folding_randomness, claimed_sum) = sumcheck_prover.compute_sumcheck_polynomials(
            claim,
            num_variables / 2,
            &vec![0.; num_variables / 2],
            &mut challenger_prover,
        );

        let z_1: Point<EF> = (0..4).map(|_| rng.gen()).collect();
        let combination_randomness: EF = rng.gen();

        sumcheck_prover.add_equality_polynomials(vec![z_1.clone()], combination_randomness);

        let f_vec = match &sumcheck_prover.f_vec {
            KOrEfMle::EF(f_vec) => f_vec,
            KOrEfMle::K(_) => panic!(),
        };
        let f_eval = f_vec.inner().as_ref().unwrap().blocking_monomial_basis_eval_at(&z_1);

        let (_, folding_randomness_2, claimed_sum) = sumcheck_prover.compute_sumcheck_polynomials(
            claimed_sum + combination_randomness * f_eval[0],
            2,
            &[0.; 2],
            &mut challenger_prover,
        );

        let z_2: Point<EF> = (0..2).map(|_| rng.gen()).collect();
        let combination_randomness_2: EF = rng.gen();

        sumcheck_prover.add_equality_polynomials(vec![z_2.clone()], combination_randomness_2);

        let f_vec = match &sumcheck_prover.f_vec {
            KOrEfMle::EF(f_vec) => f_vec,
            KOrEfMle::K(_) => panic!(),
        };
        let f_eval = f_vec.inner().as_ref().unwrap().blocking_monomial_basis_eval_at(&z_2);

        let (_, folding_randomness_3, claimed_sum) = sumcheck_prover.compute_sumcheck_polynomials(
            claimed_sum + combination_randomness_2 * f_eval[0],
            2,
            &[0.; 2],
            &mut challenger_prover,
        );

        let full_concatenated: Point<EF> = folding_randomness_3
            .iter()
            .copied()
            .chain(folding_randomness_2.iter().copied())
            .chain(folding_randomness.iter().copied())
            .collect();
        let partial_concatenated: Point<EF> = folding_randomness_3
            .iter()
            .copied()
            .chain(folding_randomness_2.iter().copied())
            .collect();
        assert_eq!(
            claimed_sum,
            (query_vector.blocking_eval_at(&full_concatenated).to_vec()[0]
                + Mle::full_monomial_basis_eq(&z_initial, &full_concatenated))
                * polynomial.blocking_eval_at(&full_concatenated).to_vec()[0]
                + combination_randomness
                    * polynomial.blocking_eval_at(&full_concatenated).to_vec()[0]
                    * Mle::full_monomial_basis_eq(&z_1, &partial_concatenated)
                + combination_randomness_2
                    * polynomial.blocking_eval_at(&full_concatenated).to_vec()[0]
                    * Mle::full_monomial_basis_eq(&z_2, &folding_randomness_3.into())
        );
    }

    #[test]
    fn test_interleave() {
        let rng = &mut thread_rng();

        let height = 1 << 5;
        let widths = [1, 2, 3, 4, 5];
        let total_width: usize = widths.iter().sum();
        let tensors: Vec<Tensor<BabyBear>> =
            widths.iter().map(|w| Tensor::rand(rng, [height, *w])).collect();

        let interleaved = interleave_chain(tensors.iter().cloned());

        assert_eq!(interleaved.sizes(), [height, total_width]);

        let tensor_concat = tensors
            .into_iter()
            .flat_map(|t| t.transpose().into_buffer().to_vec())
            .collect::<Tensor<_>>()
            .reshape([total_width, height])
            .transpose();

        for (i, (elem_1, elem_2)) in interleaved
            .clone()
            .into_buffer()
            .to_vec()
            .into_iter()
            .zip(tensor_concat.clone().into_buffer().to_vec())
            .enumerate()
        {
            assert_eq!(elem_1, elem_2, "Failed at index {i}");
        }
    }

    #[test]
    // Test the relationship between encodings (within the WHIR commit functions) and concatenations
    // of multilinears.
    fn test_multi_commit() {
        const FOLDING_FACTOR: usize = 3;
        let blowup_factor = 2;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let dft = Radix2DitParallel;

        let polynomial_1: Mle<F> = Mle::rand(&mut rng, 6, 2);
        let polynomial_2: Mle<F> = Mle::rand(&mut rng, 2, 2);

        let polynomial_concat: Mle<F> =
            Mle::new(interleave(polynomial_1.guts().clone(), polynomial_2.guts().clone()));

        let num_non_zero_entries = polynomial_concat.guts().total_len() as usize;
        let inner_evals = polynomial_concat
            .guts()
            .clone()
            .reshape([num_non_zero_entries / (1 << FOLDING_FACTOR), 1 << FOLDING_FACTOR]);

        let encoding = batch_dft::<_, F, F>(&dft, inner_evals.clone(), blowup_factor);

        let inner_evals_1 = polynomial_1.guts().clone();
        let encoding_1 = batch_dft::<_, F, F>(&dft, inner_evals_1.clone(), blowup_factor);

        let inner_evals_2 = polynomial_2.guts().clone();

        let encoding_2 = batch_dft::<_, F, F>(&dft, inner_evals_2, blowup_factor);
        let encoding_concat: Mle<F> = Mle::new(interleave(encoding_1.clone(), encoding_2.clone()));

        let mut incorrect_indices = vec![];

        for (i, (elem, other)) in encoding
            .clone()
            .into_buffer()
            .to_vec()
            .into_iter()
            .zip(encoding_concat.guts().clone().into_buffer().to_vec())
            .enumerate()
        {
            if elem != other {
                incorrect_indices.push(i);
            }
        }
        assert!(incorrect_indices.is_empty(), "Found incorrect indices: {incorrect_indices:?}");
    }

    // WHIR end-to-end tests.

    fn whir_test_generic<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField + ExtensionField<GC::F>>,
        MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    >(
        config: WhirProofShape<GC::F>,
        merkle_prover: MerkleProver,
        rounds: Rounds<Message<Mle<GC::F>>>,
    ) where
        Standard: Distribution<GC::F> + Distribution<GC::EF>,
    {
        setup_logger();

        let round_areas = rounds
            .iter()
            .map(|message| {
                message
                    .iter()
                    .map(|m| m.guts().as_slice().len())
                    .sum::<usize>()
                    .next_multiple_of(1 << config.starting_interleaved_log_height)
            })
            .collect::<Vec<_>>();
        let num_variables = round_areas.iter().sum::<usize>().next_power_of_two().ilog2() as usize;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let mut challenger_prover = GC::default_challenger();
        let mut challenger_verifier = GC::default_challenger();

        let prover = Prover::<_, _, _>::new(Radix2DitParallel, merkle_prover, config.clone());
        let merkle_verifier = MerkleTreeTcs::default();

        let mut concat_vec: Vec<GC::F> = rounds
            .iter()
            .flat_map(|round| {
                concat_transpose(round.iter().cloned()).guts().clone().into_buffer().to_vec()
            })
            .collect();

        concat_vec.resize(1 << num_variables, GC::F::zero());

        let polynomial_concat: Mle<GC::F> =
            Mle::new(Tensor::from(concat_vec).reshape([1 << num_variables, 1]));

        let point = (0..num_variables).map(|_| rng.gen()).collect::<Point<GC::EF>>();
        let eval_claim = polynomial_concat.eval_at(&point)[0];

        let mut prover_datas = Vec::new();

        for round in rounds.iter() {
            let (_, prover_data, _) = prover.commit_multilinear(round.clone()).unwrap();
            challenger_prover.observe(prover_data.commitment);
            prover_datas.push(prover_data);
        }

        let commitments = prover_datas.iter().map(|data| data.commitment).collect::<Vec<_>>();
        let now = std::time::Instant::now();

        let proof = prover
            .prove_trusted_evaluation(
                point.clone(),
                eval_claim,
                prover_datas.into_iter().collect(),
                &mut challenger_prover,
            )
            .unwrap();

        let elapsed = now.elapsed();
        tracing::debug!("Proof generation took: {:?}", elapsed);

        let proof_bytes = bincode::serialize(&proof).unwrap();
        tracing::debug!("Proof size: {} bytes", proof_bytes.len());

        let verifier = Verifier::new(merkle_verifier, config.clone(), rounds.iter().count());
        verifier.observe_commitment(&commitments, &mut challenger_verifier).unwrap();
        verifier
            .verify_trusted_evaluation(
                &commitments,
                &round_areas,
                point,
                eval_claim,
                &proof,
                &mut challenger_verifier,
            )
            .unwrap();
    }

    fn whir_test_single_round<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField + ExtensionField<GC::F>>,
        MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    >(
        config: WhirProofShape<GC::F>,
        num_variables: usize,
        merkle_prover: MerkleProver,
    ) where
        Standard: Distribution<GC::F> + Distribution<GC::EF>,
    {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let polynomial_1: Mle<GC::F> = Mle::rand(&mut rng, 2, num_variables as u32 - 3);
        let polynomial_2: Mle<GC::F> = Mle::new(Tensor::rand(
            &mut rng,
            [(1 << (num_variables as u32 - 3)) - (1 << 10) + 1, 4],
        ));
        let polynomial_3: Mle<GC::F> = Mle::rand(&mut rng, 2, num_variables as u32 - 3);

        whir_test_generic::<GC, MerkleProver>(
            config,
            merkle_prover,
            vec![vec![polynomial_1, polynomial_2, polynomial_3].into()].into_iter().collect(),
        );
    }

    fn whir_test_multi_round<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField + ExtensionField<GC::F>>,
        MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    >(
        config: WhirProofShape<GC::F>,
        num_variables: usize,
        merkle_prover: MerkleProver,
    ) where
        Standard: Distribution<GC::F> + Distribution<GC::EF>,
    {
        setup_logger();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let polynomial_1: Mle<GC::F> = Mle::rand(&mut rng, 2, num_variables as u32 - 2);
        let polynomial_2: Mle<GC::F> = Mle::rand(&mut rng, 6, num_variables as u32 - 4);
        let polynomial_3: Mle<GC::F> =
            Mle::new(Tensor::zeros_in([1 << (num_variables - 4), 1], CpuBackend));

        whir_test_generic::<GC, MerkleProver>(
            config,
            merkle_prover,
            vec![vec![polynomial_1].into(), vec![polynomial_2].into(), vec![polynomial_3].into()]
                .into_iter()
                .collect(),
        );
    }

    #[test]
    fn whir_test_multi_round_koala_bear() {
        let config = WhirProofShape::default_whir_config();
        let merkle_prover: Poseidon2KoalaBear16Prover = FieldMerkleTreeProver::default();

        whir_test_multi_round::<_, _>(config, 16, merkle_prover);
    }

    #[test]
    fn whir_test_e2e_koala_bear() {
        let config = WhirProofShape::default_whir_config();
        let merkle_prover: Poseidon2KoalaBear16Prover = FieldMerkleTreeProver::default();
        whir_test_single_round::<_, _>(config, 16, merkle_prover);
    }

    #[test]
    #[ignore = "test used for benchmarking"]
    fn whir_test_realistic_koala_bear() {
        let config = big_beautiful_whir_config::<KoalaBear>();
        let merkle_prover: Poseidon2KoalaBear16Prover = FieldMerkleTreeProver::default();
        whir_test_single_round::<_, _>(config, 28, merkle_prover);
    }

    #[test]
    fn whir_test_e2e_baby_bear() {
        let config = WhirProofShape::default_whir_config();
        let merkle_prover: Poseidon2BabyBear16Prover = FieldMerkleTreeProver::default();
        whir_test_single_round::<_, _>(config, 16, merkle_prover);
    }

    #[test]
    #[ignore = "test used for benchmarking"]
    fn whir_test_realistic_baby_bear() {
        let config = WhirProofShape::big_beautiful_whir_config();
        let merkle_prover: Poseidon2BabyBear16Prover = FieldMerkleTreeProver::default();
        whir_test_single_round::<_, _>(config, 28, merkle_prover);
    }

    #[test]
    fn jagged_whir_test_baby_bear() {
        let config = WhirProofShape::default_whir_config();
        let merkle_prover: Poseidon2BabyBear16Prover = FieldMerkleTreeProver::default();

        test_jagged_whir_generic::<_, _>(config, merkle_prover);
    }

    fn test_jagged_whir_generic<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField + ExtensionField<GC::F>>,
        MerkleProver: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend>,
    >(
        config: WhirProofShape<GC::F>,
        merkle_prover: MerkleProver,
    ) where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let row_counts_rounds = vec![vec![1 << 10, 0, (1 << 9) - (1 << 7) - 1], vec![1 << 9]];
        let column_counts_rounds = vec![vec![32, 45, 32], vec![32]];
        let num_rounds = row_counts_rounds.len();
        let max_log_row_count = 12;

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
                            let mle = Tensor::<GC::F>::rand(&mut rng, [*num_rows, *num_cols]);
                            PaddedMle::padded_with_zeros(Arc::new(Mle::new(mle)), max_log_row_count)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Rounds<_>>();

        let merkle_verifier = MerkleTreeTcs::default();
        let verifier = Verifier::<GC>::new(merkle_verifier, config.clone(), num_rounds);

        let jagged_verifier =
            JaggedPcsVerifier::<GC, Verifier<GC>>::new(verifier, max_log_row_count as usize);

        let prover = Prover::<_, _, _>::new(Radix2DitParallel, merkle_prover, config.clone());

        let jagged_prover =
            JaggedProver::<GC, WhirProof<GC>, Prover<GC, MerkleProver, Radix2DitParallel>>::new(
                max_log_row_count as usize,
                prover,
                JaggedEvalSumcheckProver::default(),
            );

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
            .into_iter()
            .map(|round| round.into_iter().flat_map(|v| v.into_iter()).collect())
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
