use std::{iter, marker::PhantomData, sync::Arc};

use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::{
    CanObserve, CanSampleBits, FieldChallenger, IopCtx, VariableLengthChallenger,
};
use slop_commit::Rounds;
use slop_merkle_tree::MerkleTreeOpeningAndProof;
use slop_multilinear::{
    monomial_basis_evals_blocking, partial_lagrange_blocking, Mle, Point, ToMle,
};
use slop_tensor::Tensor;
use slop_utils::reverse_bits_len;
use slop_whir::{
    config::WhirProofShape,
    verifier::{map_to_pow, ParsedCommitment, ProofOfWork, SumcheckPoly, WhirProof},
};
use sp1_gpu_basefold::{
    encode_batch, DeviceGrindingChallenger, GrindingPowCudaProver, SpparkDftKoalaBear,
};
use sp1_gpu_cudart::{DeviceTensor, TaskScope};
use sp1_gpu_merkle_tree::{CudaTcsProver, MerkleTreeProverData};
use sp1_gpu_utils::{Ext, Felt};

use slop_commit::Message;

// --- Local copies of private functions from slop-whir ---

fn interleave<F: Field>(left: Tensor<F>, right: Tensor<F>) -> Tensor<F> {
    assert_eq!(left.sizes().len(), 2);
    assert_eq!(right.sizes().len(), 2);
    assert_eq!(left.sizes()[0], right.sizes()[0]);
    let width_1 = left.sizes()[1];
    let width_2 = right.sizes()[1];
    let height = left.sizes()[0];

    left.into_buffer()
        .chunks_exact(width_1)
        .zip(right.into_buffer().chunks_exact(width_2))
        .flat_map(|(l, r)| l.iter().chain(r.iter()).copied().collect::<Vec<_>>())
        .collect::<Tensor<_, CpuBackend>>()
        .reshape([height, width_1 + width_2])
}

fn interleave_chain<F: Field>(iter: impl Iterator<Item = Tensor<F>>) -> Tensor<F> {
    let mut iter = iter.peekable();
    let first = iter.next().unwrap();
    iter.fold(first, |acc, x| interleave(acc, x))
}

/// GPU-accelerated WHIR polynomial commitment scheme prover.
///
/// Uses GPU for Merkle tree commitment/openings and proof-of-work grinding,
/// while keeping the sumcheck computation on CPU.
pub struct WhirCudaProver<GC: IopCtx, P: CudaTcsProver<GC>> {
    tcs_prover: P,
    scope: TaskScope,
    config: WhirProofShape<GC::F>,
    _marker: PhantomData<GC>,
}

/// Prover data produced by the GPU WHIR commit phase.
pub struct WhirCudaProverData<GC: IopCtx> {
    pub merkle_prover_data: MerkleTreeProverData<GC::Digest>,
    pub committed_data: Tensor<GC::F, TaskScope>,
    /// The interleaved polynomial (inner_evals flattened), same order as CPU `WhirProverData::polynomial`.
    pub polynomial: Mle<GC::F>,
    /// The pre-interleave concatenated polynomial.
    pub precommitment_poly: Mle<GC::F>,
    pub commitment: GC::Digest,
}

impl<GC: IopCtx> ToMle<GC::F> for WhirCudaProverData<GC> {
    fn interleaved_mles(&self) -> Message<Mle<GC::F, CpuBackend>> {
        Message::from(self.precommitment_poly.clone())
    }
}

impl<GC, P> WhirCudaProver<GC, P>
where
    GC: IopCtx<F = Felt, EF = Ext>,
    P: CudaTcsProver<GC>,
    GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
{
    pub fn new(tcs_prover: P, scope: TaskScope, config: WhirProofShape<GC::F>) -> Self {
        Self { tcs_prover, scope, config, _marker: PhantomData }
    }

    /// Commit to multilinear polynomials using GPU-accelerated encoding and Merkle commitment.
    ///
    /// Mirrors the CPU `commit_multilinear` in `slop-whir/src/prover.rs:542-582`.
    pub fn commit_multilinear(
        &self,
        mles: Message<Mle<GC::F>>,
    ) -> (GC::Digest, WhirCudaProverData<GC>, usize) {
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

        // GPU DFT operates along dim 1, while CPU operates along dim 0.
        // CPU Merkle expects [height, width], GPU Merkle expects [width, height].
        // So we transpose inner_evals before GPU DFT:
        //   CPU: [interleaved_h, num_polys] → DFT dim 0 → [interleaved_h*blowup, num_polys]
        //   GPU: [num_polys, interleaved_h] → DFT dim 1 → [num_polys, interleaved_h*blowup]
        let device_tensor =
            DeviceTensor::from_host(&inner_evals, &self.scope).unwrap().transpose().into_inner();

        let num_polys = inner_evals.sizes()[1];
        let interleaved_h = inner_evals.sizes()[0];
        let mut encoded = Tensor::<Felt, TaskScope>::with_sizes_in(
            [num_polys, interleaved_h << self.config.starting_log_inv_rate],
            self.scope.clone(),
        );
        unsafe { encoded.assume_init() };

        let encoder = SpparkDftKoalaBear::default();
        encode_batch(
            encoder,
            self.config.starting_log_inv_rate as u32,
            device_tensor.as_view(),
            &mut encoded,
        )
        .unwrap();

        // Merkle commit
        let (commitment, merkle_prover_data) = self.tcs_prover.commit_tensors(&encoded).unwrap();

        // Store interleaved polynomial (same as CPU WhirProverData::polynomial)
        let polynomial = Mle::new(inner_evals.clone().reshape([num_non_zero_entries, 1]));

        let witness = WhirCudaProverData {
            merkle_prover_data,
            committed_data: encoded,
            polynomial,
            precommitment_poly: concatenated_mles,
            commitment,
        };
        (witness.commitment, witness, added_zeroes)
    }

    /// Parse commitment data and prepare for proving.
    /// Mirrors CPU `parse_commitment_data` in `prover.rs:157-260`.
    fn parse_commitment_data(
        &self,
        challenger: &mut GC::Challenger,
        config: &WhirProofShape<GC::F>,
        rounds: &Rounds<WhirCudaProverData<GC>>,
    ) -> (ParsedCommitment<GC>, Mle<GC::EF>) {
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

        // Build the concatenated polynomial on CPU (same logic as CPU prover).
        // Uses r.polynomial (interleaved order), matching CPU WhirProverData::polynomial.
        let concatenated_polynomial = if num_to_add != 0 {
            interleave_chain(
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
                    .chain(std::iter::once(Tensor::from(vec![GC::F::zero(); num_to_add]).reshape(
                        [
                            1 << config.starting_interleaved_log_height,
                            num_to_add / (1 << config.starting_interleaved_log_height),
                        ],
                    ))),
            )
            .into_buffer()
            .to_vec()
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

        let concatenated_polynomial: Mle<GC::F> =
            Mle::new(Tensor::from(concatenated_polynomial).reshape([1 << num_variables, 1]));

        let ood_answers: Vec<GC::EF> = ood_points
            .iter()
            .map(|point| concatenated_polynomial.blocking_monomial_basis_eval_at(point)[0])
            .collect();

        challenger.observe_constant_length_extension_slice(&ood_answers);

        let parsed_commitment = ParsedCommitment {
            commitment: rounds.iter().map(|r| r.commitment).collect(),
            ood_points,
            ood_answers,
        };

        // Convert base field polynomial to extension field
        let ef_polynomial: Mle<GC::EF> = Mle::new(
            concatenated_polynomial
                .guts()
                .as_slice()
                .iter()
                .map(|&x| GC::EF::from(x))
                .collect::<Tensor<_>>()
                .reshape([1 << num_variables, 1]),
        );

        (parsed_commitment, ef_polynomial)
    }

    /// Main proving function. Mirrors CPU `prove` in `prover.rs:262-529`.
    pub fn prove(
        &self,
        query_vector: Mle<GC::EF>,
        witness_data: Rounds<WhirCudaProverData<GC>>,
        claim: GC::EF,
        challenger: &mut GC::Challenger,
        config: &WhirProofShape<GC::F>,
    ) -> WhirProof<GC> {
        let n_rounds = config.round_parameters.len();

        let (parsed_commitment, polynomial) =
            self.parse_commitment_data(challenger, config, &witness_data);

        let claim_batching_randomness: GC::EF = challenger.sample_ext_element();
        let claimed_sum: GC::EF = claim_batching_randomness
            .powers()
            .zip(std::iter::once(&claim).chain(&parsed_commitment.ood_answers))
            .map(|(r, &v)| r * v)
            .sum();
        let mut parsed_commitments = Vec::with_capacity(n_rounds);
        parsed_commitments.push(parsed_commitment.clone());

        let num_variables = query_vector.num_variables() as usize;

        // Initialize sumcheck prover on CPU
        let mut sumcheck_prover = CpuSumcheckProver::<GC>::new(
            polynomial,
            query_vector,
            parsed_commitment.ood_points.clone(),
            claim_batching_randomness,
        );

        let (initial_sumcheck_polynomials, mut folding_randomness, mut claimed_sum) =
            sumcheck_prover.compute_sumcheck_polynomials(
                claimed_sum,
                num_variables - config.starting_interleaved_log_height,
                &config.starting_folding_pow_bits,
                challenger,
                &self.scope,
            );

        let mut generator = config.domain_generator;
        let mut merkle_proofs = Vec::with_capacity(n_rounds);
        let mut query_proof_of_works = Vec::with_capacity(n_rounds);
        let mut sumcheck_polynomials = Vec::with_capacity(n_rounds);

        let mut prev_domain_log_size = config.starting_domain_log_size;
        let mut prev_folding_factor = num_variables - config.starting_interleaved_log_height;
        #[allow(clippy::type_complexity)]
        let (mut prev_prover_data, mut prev_committed_data): (
            Rounds<MerkleTreeProverData<GC::Digest>>,
            Rounds<Arc<Tensor<GC::F, TaskScope>>>,
        ) = witness_data
            .into_iter()
            .map(|r| (r.merkle_prover_data, Arc::new(r.committed_data)))
            .unzip();

        for round_index in 0..n_rounds {
            let round_params = &config.round_parameters[round_index];

            // Get the folded polynomial from the sumcheck prover
            let num_nonzero_entries = sumcheck_prover.f_vec.num_non_zero_entries();
            let inner_evals = sumcheck_prover.f_vec.guts().clone().reshape([
                num_nonzero_entries.div_ceil(1 << round_params.folding_factor),
                1 << round_params.folding_factor,
            ]);

            // DFT encode on CPU (extension field), then flatten to base for Merkle
            let dft = slop_dft::p3::Radix2DitParallel;
            let encoding =
                batch_dft::<_, GC::F, GC::EF>(&dft, inner_evals, round_params.log_inv_rate);
            let encoding_base = encoding.flatten_to_base();

            // Upload encoding to GPU for Merkle commit.
            // CPU encoding_base is [height, width] (CPU convention).
            // GPU commit_tensors expects [width, height], so we transpose.
            let device_encoding = DeviceTensor::from_host(&encoding_base, &self.scope)
                .unwrap()
                .transpose()
                .into_inner();

            let (commitment, prover_data) =
                self.tcs_prover.commit_tensors(&device_encoding).unwrap();

            // Observe the commitment
            CanObserve::<GC::Digest>::observe(challenger, commitment);

            // Sample and evaluate OOD points
            let ood_points: Vec<Point<GC::EF>> = (0..round_params.ood_samples)
                .map(|_| {
                    (0..sumcheck_prover.f_vec.num_variables())
                        .map(|_| challenger.sample_ext_element())
                        .collect::<Vec<GC::EF>>()
                        .into()
                })
                .collect();

            let ood_answers: Vec<GC::EF> = ood_points
                .iter()
                .map(|point| sumcheck_prover.f_vec.blocking_monomial_basis_eval_at(point)[0])
                .collect();

            challenger.observe_constant_length_extension_slice(&ood_answers);

            parsed_commitments.push(ParsedCommitment::<GC> {
                commitment: vec![commitment].into_iter().collect(),
                ood_points: ood_points.clone(),
                ood_answers: ood_answers.clone(),
            });

            // Sample STIR query indices
            let id_query_indices = (0..round_params.num_queries)
                .map(|_| challenger.sample_bits(prev_domain_log_size))
                .collect::<Vec<_>>();
            let id_query_values: Vec<GC::F> = id_query_indices
                .iter()
                .map(|val| reverse_bits_len(*val, prev_domain_log_size))
                .map(|pos| generator.exp_u64(pos as u64))
                .collect();

            let claim_batching_randomness: GC::EF = challenger.sample_ext_element();

            query_proof_of_works.push(GrindingPowCudaProver::grind(
                challenger,
                round_params.queries_pow_bits.ceil() as usize,
                &self.scope,
            ));

            // Compute Merkle openings and proofs on GPU
            let merkle_openings: Vec<Tensor<GC::F>> = prev_committed_data
                .iter()
                .map(|data| self.tcs_prover.compute_openings_at_indices(data, &id_query_indices))
                .collect();

            let num_openings: usize = merkle_openings.iter().map(|o| o.sizes()[1]).sum();

            let merkle_proof: Vec<_> = prev_prover_data
                .into_iter()
                .map(|data| {
                    self.tcs_prover.prove_openings_at_indices(&data, &id_query_indices).unwrap()
                })
                .collect();
            let merkle_proof = merkle_proof
                .into_iter()
                .zip(merkle_openings)
                .map(|(proof, opening)| MerkleTreeOpeningAndProof { values: opening, proof })
                .collect::<Vec<_>>();

            // Read Merkle values and compute STIR values
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

            // Update claimed sum
            claimed_sum = claim_batching_randomness
                .powers()
                .zip(iter::once(&claimed_sum).chain(&ood_answers).chain(&stir_values))
                .map(|(r, &v)| v * r)
                .sum();

            let new_eq_polys = [
                ood_points,
                id_query_values
                    .into_iter()
                    .map(|point| {
                        map_to_pow(point, sumcheck_prover.f_vec.num_variables() as usize)
                            .to_extension()
                    })
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
                    &self.scope,
                );

            folding_randomness = round_folding_randomness;
            claimed_sum = round_claimed_sum;

            sumcheck_polynomials.push(round_sumcheck_polynomials);

            // Update for next round
            generator = generator.square();
            prev_folding_factor = round_params.folding_factor;
            prev_domain_log_size = round_params.evaluation_domain_log_size;
            prev_prover_data = vec![prover_data].into_iter().collect();
            prev_committed_data = vec![Arc::new(device_encoding)].into_iter().collect();
        }

        // Final round
        let final_polynomial = sumcheck_prover.f_vec.guts().clone().into_buffer().to_vec();
        challenger.observe_constant_length_extension_slice(&final_polynomial);

        let final_id_indices = (0..config.final_queries)
            .map(|_| challenger.sample_bits(prev_domain_log_size))
            .collect::<Vec<_>>();

        let final_pow = GrindingPowCudaProver::grind(
            challenger,
            config.final_pow_bits.ceil() as usize,
            &self.scope,
        );

        // Final Merkle openings on GPU
        assert!(prev_committed_data.len() == 1);
        let final_merkle_openings =
            self.tcs_prover.compute_openings_at_indices(&prev_committed_data[0], &final_id_indices);

        assert!(prev_prover_data.len() == 1);
        let final_merkle_proof = self
            .tcs_prover
            .prove_openings_at_indices(&prev_prover_data[0], &final_id_indices)
            .unwrap();

        let final_merkle_proof =
            MerkleTreeOpeningAndProof { values: final_merkle_openings, proof: final_merkle_proof };

        let (final_sumcheck_polynomials, _, _) = sumcheck_prover.compute_sumcheck_polynomials(
            claimed_sum,
            config.final_poly_log_degree,
            &config.final_folding_pow_bits,
            challenger,
            &self.scope,
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

    /// Prove trusted evaluation. This is the main entry point matching the
    /// `MultilinearPcsProver` trait pattern.
    pub fn prove_trusted_evaluation(
        &self,
        eval_point: Point<GC::EF>,
        evaluation_claim: GC::EF,
        prover_data: Rounds<WhirCudaProverData<GC>>,
        challenger: &mut GC::Challenger,
    ) -> WhirProof<GC> {
        let (folding_point, stacked_point) = eval_point
            .split_at(eval_point.dimension() - self.config.starting_interleaved_log_height);
        let eval_point = stacked_point
            .iter()
            .copied()
            .chain(folding_point.iter().copied())
            .collect::<Point<_>>();
        self.prove(
            Mle::new(partial_lagrange_blocking(&eval_point)),
            prover_data,
            evaluation_claim,
            challenger,
            &self.config,
        )
    }
}

/// CPU-side sumcheck prover that uses GPU grinding for proof-of-work.
/// Mirrors the CPU `SumcheckProver` from `slop-whir/src/prover.rs` but with
/// GPU-accelerated proof-of-work grinding.
struct CpuSumcheckProver<GC: IopCtx> {
    f_vec: Mle<GC::EF>,
    eq_vec: Mle<GC::EF>,
}

impl<GC> CpuSumcheckProver<GC>
where
    GC: IopCtx<F = Felt, EF = Ext>,
    GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
{
    fn new(
        f_vec: Mle<GC::EF>,
        query_vector: Mle<GC::EF>,
        eq_points: Vec<Point<GC::EF>>,
        combination_randomness: GC::EF,
    ) -> Self {
        let mut acc = combination_randomness;
        let mut eq_vec = query_vector.into_guts().into_buffer().to_vec();
        for mle in eq_points.iter().map(monomial_basis_evals_blocking) {
            Mle::new(mle)
                .hypercube_iter()
                .enumerate()
                .for_each(|(i, val)| eq_vec[i] += acc * val[0]);
            acc *= combination_randomness;
        }

        // Pad f_vec with zeros to match eq_vec size
        let f_len = f_vec.guts().as_slice().len();
        let eq_len = eq_vec.len();
        let f_vec = if f_len < eq_len {
            let mut buf = f_vec.guts().clone().into_buffer().to_vec();
            buf.resize(eq_len, GC::EF::zero());
            Mle::new(Tensor::from(buf).reshape([eq_len, 1]))
        } else {
            f_vec
        };

        CpuSumcheckProver { f_vec, eq_vec: eq_vec.into() }
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
        scope: &TaskScope,
    ) -> (Vec<(SumcheckPoly<GC::EF>, ProofOfWork<GC>)>, Vec<GC::EF>, GC::EF) {
        let mut res = Vec::with_capacity(num_rounds);
        let mut folding_randomness = Vec::with_capacity(num_rounds);

        for round_pow_bits in &pow_bits[..num_rounds] {
            // Compute c0 and c2 via inner product
            let (c0, c2) =
                inner_prod_ef(self.f_vec.guts().as_slice(), self.eq_vec.guts().as_slice());

            let c1 = claimed_sum - c0.double() - c2;
            let sumcheck_poly = SumcheckPoly([c0, c1, c2]);

            challenger.observe_constant_length_extension_slice(&sumcheck_poly.0);
            let folding_randomness_single: GC::EF = challenger.sample_ext_element();
            let pow =
                GrindingPowCudaProver::grind(challenger, round_pow_bits.ceil() as usize, scope);
            claimed_sum = sumcheck_poly.evaluate_at_point(folding_randomness_single);
            res.push((sumcheck_poly, pow));
            folding_randomness.push(folding_randomness_single);

            self.f_vec = self.f_vec.fix_last_variable(folding_randomness_single);
            self.eq_vec = self.eq_vec.fix_last_variable(folding_randomness_single);
        }
        folding_randomness.reverse();

        // Pad f_vec to match eq_vec size after sumcheck rounds
        let f_len = self.f_vec.num_non_zero_entries();
        let eq_len = self.eq_vec.guts().as_slice().len();
        if f_len < eq_len {
            let num_added_zeroes = eq_len - f_len;
            let mut new_buffer = self.f_vec.guts().clone().into_buffer();
            new_buffer.extend_from_slice(&vec![GC::EF::zero(); num_added_zeroes]);
            let num_variables = self.f_vec.num_variables();
            self.f_vec = Mle::new(Tensor::from(new_buffer).reshape([1 << num_variables, 1]));
        }

        (res, folding_randomness, claimed_sum)
    }
}

/// Compute the inner product for the sumcheck polynomial.
/// Returns (c0, c2) where:
/// - c0 = sum over i of f[2i] * eq[2i]
/// - c2 = sum over i of (f[2i+1] - f[2i]) * (eq[2i+1] - eq[2i])
fn inner_prod_ef(f_slice: &[Ext], eq_slice: &[Ext]) -> (Ext, Ext) {
    f_slice
        .chunks_exact(2)
        .zip(eq_slice.chunks_exact(2))
        .map(|(f_chunk, eq_chunk)| {
            let f0 = f_chunk[0];
            let f1 = f_chunk[1];
            let v0 = eq_chunk[0];
            let v1 = eq_chunk[1];
            (v0 * f0, (v1 - v0) * (f1 - f0))
        })
        .fold((Ext::zero(), Ext::zero()), |(acc0, acc2), (v0, v2)| (acc0 + v0, acc2 + v2))
}

/// Batch DFT encoding. Same as the CPU version from slop-whir.
fn batch_dft<D, F, EF>(dft: &D, data: Tensor<EF>, log_blowup: usize) -> Tensor<EF>
where
    F: Field,
    EF: ExtensionField<F>,
    D: slop_dft::Dft<F>,
{
    assert_eq!(data.sizes().len(), 2, "Expected a 2D tensor");
    let base_tensor = data.flatten_to_base();
    let base_tensor =
        dft.dft(&base_tensor, log_blowup, slop_dft::DftOrdering::BitReversed, 0).unwrap();
    base_tensor.into_extension()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_commit::Rounds;
    use slop_dft::p3::Radix2DitParallel;
    use slop_koala_bear::KoalaBearDegree4Duplex;
    use slop_merkle_tree::{FieldMerkleTreeProver, MerkleTreeTcs, Poseidon2KoalaBear16Prover};
    use slop_multilinear::{MultilinearPcsProver, MultilinearPcsVerifier};
    use slop_whir::{config::WhirProofShape, prover::Prover, verifier::Verifier};
    use sp1_gpu_cudart::run_sync_in_place;
    use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};

    use super::*;

    type F = Felt;
    type EF = BinomialExtensionField<F, 4>;
    type GC = KoalaBearDegree4Duplex;

    /// Concatenate and transpose MLEs for evaluation claim computation.
    fn concat_transpose_local<F2: Field>(
        iter: impl Iterator<Item = Arc<Mle<F2>>> + Clone,
    ) -> Mle<F2> {
        let total_len = iter.clone().map(|m| m.guts().as_slice().len()).sum::<usize>();
        let mut result = Vec::with_capacity(total_len);
        for mle in iter {
            result.extend(mle.guts().transpose().as_slice().iter().copied());
        }
        Mle::new(Tensor::from(result).reshape([total_len, 1]))
    }

    #[test]
    fn test_whir_gpu_vs_cpu() {
        let config = WhirProofShape::default_whir_config();
        let num_variables: u32 = 16;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let polynomial_1: Mle<F> = Mle::rand(&mut rng, 2, num_variables - 3);
        let polynomial_2: Mle<F> =
            Mle::new(Tensor::rand(&mut rng, [(1 << (num_variables - 3)) - (1 << 10) + 1, 4]));
        let polynomial_3: Mle<F> = Mle::rand(&mut rng, 2, num_variables - 3);

        let rounds: Rounds<Message<Mle<F>>> =
            vec![vec![polynomial_1, polynomial_2, polynomial_3].into()].into_iter().collect();

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

        let total_vars = round_areas.iter().sum::<usize>().next_power_of_two().ilog2() as usize;

        let point = Point::<EF>::rand(&mut rng, total_vars as u32);

        // Compute evaluation claim
        let mut concat_vec: Vec<F> = rounds
            .iter()
            .flat_map(|round| {
                concat_transpose_local(round.iter().cloned()).guts().clone().into_buffer().to_vec()
            })
            .collect();
        concat_vec.resize(1 << total_vars, F::zero());
        let polynomial_concat: Mle<F> =
            Mle::new(Tensor::from(concat_vec).reshape([1 << total_vars, 1]));
        let eval_claim = polynomial_concat.eval_at(&point)[0];

        // ===== CPU WHIR prover =====
        let merkle_prover: Poseidon2KoalaBear16Prover = FieldMerkleTreeProver::default();
        let cpu_prover = Prover::<GC, _, _>::new(Radix2DitParallel, merkle_prover, config.clone());

        let mut cpu_challenger = GC::default_challenger();

        let mut cpu_prover_datas = Vec::new();
        let mut cpu_commitments = Vec::new();
        for round in rounds.iter() {
            let (commitment, prover_data, _) =
                cpu_prover.commit_multilinear(round.clone()).unwrap();
            cpu_challenger.observe(commitment);
            cpu_commitments.push(commitment);
            cpu_prover_datas.push(prover_data);
        }

        let cpu_proof = cpu_prover
            .prove_trusted_evaluation(
                point.clone(),
                eval_claim,
                cpu_prover_datas.into_iter().collect(),
                &mut cpu_challenger,
            )
            .unwrap();

        // Verify CPU proof
        let merkle_verifier = MerkleTreeTcs::default();
        let verifier = Verifier::<GC>::new(merkle_verifier, config.clone(), rounds.iter().count());
        let mut verify_challenger = GC::default_challenger();
        verifier.observe_commitment(&cpu_commitments, &mut verify_challenger).unwrap();
        verifier
            .verify_trusted_evaluation(
                &cpu_commitments,
                &round_areas,
                point.clone(),
                eval_claim,
                &cpu_proof,
                &mut verify_challenger,
            )
            .unwrap();

        // ===== GPU WHIR prover =====
        run_sync_in_place(|scope| {
            let gpu_tcs_prover = Poseidon2SP1Field16CudaProver::new(&scope);
            let gpu_prover =
                WhirCudaProver::<GC, _>::new(gpu_tcs_prover, scope.clone(), config.clone());

            let mut gpu_challenger = GC::default_challenger();

            let mut gpu_prover_datas = Vec::new();
            for round in rounds.iter() {
                let (_, prover_data, _) = gpu_prover.commit_multilinear(round.clone());
                gpu_challenger.observe(prover_data.commitment);
                gpu_prover_datas.push(prover_data);
            }

            let gpu_commitments: Vec<_> = gpu_prover_datas.iter().map(|d| d.commitment).collect();

            // Check commitments match
            for (i, (cpu_c, gpu_c)) in
                cpu_commitments.iter().zip(gpu_commitments.iter()).enumerate()
            {
                assert_eq!(cpu_c, gpu_c, "Commitment mismatch at round {i}");
            }

            let gpu_proof = gpu_prover.prove_trusted_evaluation(
                point.clone(),
                eval_claim,
                gpu_prover_datas.into_iter().collect(),
                &mut gpu_challenger,
            );

            // Verify GPU proof
            let merkle_verifier = MerkleTreeTcs::default();
            let verifier =
                Verifier::<GC>::new(merkle_verifier, config.clone(), rounds.iter().count());
            let mut verify_challenger = GC::default_challenger();
            verifier.observe_commitment(&gpu_commitments, &mut verify_challenger).unwrap();
            verifier
                .verify_trusted_evaluation(
                    &gpu_commitments,
                    &round_areas,
                    point.clone(),
                    eval_claim,
                    &gpu_proof,
                    &mut verify_challenger,
                )
                .unwrap();
        })
        .unwrap();
    }
}
