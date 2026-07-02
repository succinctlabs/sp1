use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, TwoAdicField};
use slop_challenger::{
    CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx,
    VariableLengthChallenger,
};
use slop_commit::Rounds;
use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcs, MerkleTreeTcsError};
use slop_multilinear::{BatchPcsVerifier, OracleEval, Point};
use slop_utils::reverse_bits_len;
use thiserror::Error;

pub use slop_primitives::FriConfig;

/// The number of bits to grind in sampling the batching randomness.
pub const BATCH_GRINDING_BITS: usize = 5;

#[derive(Clone)]
pub struct BasefoldVerifier<GC: IopCtx> {
    pub fri_config: crate::FriConfig<GC::F>,
    pub tcs: MerkleTreeTcs<GC>,
    pub num_expected_commitments: usize,
    pub num_encoding_variables: u32,
}

impl<GC: IopCtx> std::fmt::Debug for BasefoldVerifier<GC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasefoldVerifier")
            .field("fri_config", &self.fri_config)
            .field("num_expected_commitments", &self.num_expected_commitments)
            .finish()
    }
}

impl<GC: IopCtx> BasefoldVerifier<GC> {
    pub fn new(
        fri_config: crate::FriConfig<GC::F>,
        num_expected_commitments: usize,
        num_encoding_variables: u32,
    ) -> Self {
        assert_ne!(num_expected_commitments, 0, "commitment must exist");
        Self {
            fri_config,
            tcs: MerkleTreeTcs::default(),
            num_expected_commitments,
            num_encoding_variables,
        }
    }
}

#[derive(Error)]
pub enum BaseFoldVerifierError<TcsError> {
    #[error("Sumcheck and FRI commitments length mismatch")]
    SumcheckFriLengthMismatch,
    #[error("Query failed to verify: {0}")]
    TcsError(#[from] TcsError),
    #[error("Sumcheck error")]
    Sumcheck,
    #[error("Invalid proof of work witness")]
    Pow,
    #[error("Invalid batch grinding witness")]
    BatchPow,
    #[error("Query value mismatch")]
    QueryValueMismatch,
    #[error("query final polynomial mismatch")]
    QueryFinalPolyMismatch,
    #[error("sumcheck final polynomial mismatch")]
    SumcheckFinalPolyMismatch,
    #[error("incorrect shape of proof")]
    IncorrectShape,
    #[error("instance overflows the field two_adicity")]
    TwoAdicityOverflow,
}

impl<TcsError: std::fmt::Display> std::fmt::Debug for BaseFoldVerifierError<TcsError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseFoldVerifierError::SumcheckFriLengthMismatch => {
                write!(f, "sumcheck and FRI commitments length mismatch")
            }
            BaseFoldVerifierError::TcsError(e) => write!(f, "tensor opening error: {e}"),
            BaseFoldVerifierError::Sumcheck => write!(f, "sumcheck error"),
            BaseFoldVerifierError::Pow => write!(f, "invalid proof of work witness"),
            BaseFoldVerifierError::BatchPow => {
                write!(f, "invalid batch grinding witness")
            }
            BaseFoldVerifierError::QueryValueMismatch => write!(f, "query value mismatch"),
            BaseFoldVerifierError::QueryFinalPolyMismatch => {
                write!(f, "query final polynomial mismatch")
            }
            BaseFoldVerifierError::SumcheckFinalPolyMismatch => {
                write!(f, "sumcheck final polynomial mismatch")
            }
            BaseFoldVerifierError::IncorrectShape => {
                write!(f, "incorrect shape of proof")
            }
            BaseFoldVerifierError::TwoAdicityOverflow => {
                write!(f, "instance overflows the field two_adicity")
            }
        }
    }
}

/// The grinding witness for the batching randomness sampled before BaseFold.
///
/// Produced and verified by whichever layer batches several evaluation claims together; it is
/// carried alongside a [`BasefoldProof`] rather than inside it.
pub type BatchGrindingWitness<GC> = <<GC as IopCtx>::Challenger as GrindingChallenger>::Witness;

/// A proof of a Basefold evaluation claim.
///
/// This proof carries no batch grinding witness. When several evaluation claims are batched
/// together before BaseFold (see `BasefoldProver::prove_trusted_mle_evaluations`), the batch
/// grinding witness is produced and verified separately, alongside this proof, by whichever layer
/// performs the batching.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldProof<GC: IopCtx> {
    /// The univariate polynomials that are used in the sumcheck part of the BaseFold protocol.
    pub univariate_messages: Vec<[GC::EF; 2]>,
    /// The FRI parts of the proof.
    /// The commitments to the folded polynomials produced in the commit phase.
    pub fri_commitments: Vec<GC::Digest>,
    /// The query openings for the individual multilinear polynmomials.
    ///
    /// The vector is indexed by the batch number.
    pub component_polynomials_query_openings_and_proofs: Vec<MerkleTreeOpeningAndProof<GC>>,
    /// The query openings and the FRI query proofs for the FRI query phase.
    pub query_phase_openings_and_proofs: Vec<MerkleTreeOpeningAndProof<GC>>,
    /// The prover performs FRI until we reach a polynomial of degree 0, and return the constant
    /// value of this polynomial.
    pub final_poly: GC::EF,
    /// Proof-of-work witness.
    pub pow_witness: <<GC as IopCtx>::Challenger as GrindingChallenger>::Witness,
}

impl<GC: IopCtx> BasefoldVerifier<GC>
where
    GC::F: TwoAdicField,
{
    /// Verify an already-batched MLE claim.
    ///
    /// # Parameters
    /// - `commitment`: Merkle root of the committed (base-field) tensor
    /// - `point`: Evaluation point in the extension field
    /// - `eval_claim`: Claimed evaluation of the batched MLE at `point`
    /// - `proof`: The Basefold proof to verify
    /// - `oracle_evaluator`: Converts the (already Merkle-verified) leaf values opened at a single
    ///   query into the value of the *virtual* oracle the proof is about (see [`OracleEval`]). It is
    ///   called once per query with the opened values for that query grouped by commitment as
    ///   [`Rounds`] (one round per commitment, in commitment order) and the sampled query index.
    /// - `challenger`: Fiat-Shamir challenger (state must match the prover's)
    pub fn verify_from_prebatched_inputs(
        &self,
        commitments: &[GC::Digest],
        mut point: Point<GC::EF>,
        eval_claim: GC::EF,
        proof: &BasefoldProof<GC>,
        oracle_evaluator: impl OracleEval<GC::F, GC::EF>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), BaseFoldVerifierError<MerkleTreeTcsError>> {
        // number of oracle opening proofs matches number of oracles
        if proof.component_polynomials_query_openings_and_proofs.len() != commitments.len()
            || commitments.len() != self.num_expected_commitments
        {
            return Err(BaseFoldVerifierError::IncorrectShape);
        }

        // Assert correctness of shape.
        if proof.fri_commitments.len() != proof.univariate_messages.len()
            || proof.fri_commitments.len() != point.dimension()
            || proof.univariate_messages.is_empty()
        {
            return Err(BaseFoldVerifierError::SumcheckFriLengthMismatch);
        }

        // The prover messages correspond to fixing the last coordinate first, so we reverse the
        // underlying point for the verification.
        point.reverse();

        // Sample the challenges used for FRI folding and BaseFold random linear combinations.
        // Observe the number of FRI rounds. In principle, the prover should already be
        // bound to this length because it is deducible from the shape of the openings in
        // `proof.component_polynomials_query_openings_and_proofs` and the prover is bound to those,
        // but we observe it here for security.
        let len = proof.fri_commitments.len();
        challenger.observe(GC::F::from_canonical_usize(len));
        let betas = proof
            .fri_commitments
            .iter()
            .zip_eq(proof.univariate_messages.iter())
            .map(|(commitment, poly)| {
                challenger.observe_constant_length_extension_slice(poly);
                challenger.observe(*commitment);
                challenger.sample_ext_element::<GC::EF>()
            })
            .collect::<Vec<_>>();

        // Check the consistency of the first univariate message with the claimed evaluation. The
        // first_poly is supposed to be `vals(X_0, X_1, ..., X_{d-1}, 0), vals(X_0, X_1, ...,
        // X_{d-1}, 1)`. Given this, the claimed evaluation should be `(1 - X_d) *
        // first_poly[0] + X_d * first_poly[1]`.
        let first_poly = proof.univariate_messages[0];
        if eval_claim != (GC::EF::one() - *point[0]) * first_poly[0] + *point[0] * first_poly[1] {
            println!("failed in first_poly");
            return Err(BaseFoldVerifierError::Sumcheck);
        };

        // Fold the two messages into a single evaluation claim for the next round, using the
        // sampled randomness.
        let mut expected_eval = first_poly[0] + betas[0] * first_poly[1];

        // Check round-by-round consistency between the successive sumcheck univariate messages.
        for (i, (poly, beta)) in
            proof.univariate_messages[1..].iter().zip_eq(betas[1..].iter()).enumerate()
        {
            // The check is similar to the one for `first_poly`.
            let i = i + 1;
            if expected_eval != (GC::EF::one() - *point[i]) * poly[0] + *point[i] * poly[1] {
                println!("failed in round {i}");
                return Err(BaseFoldVerifierError::Sumcheck);
            }

            // Fold the two pieces of the message.
            expected_eval = poly[0] + *beta * poly[1];
        }

        challenger.observe_ext_element(proof.final_poly);

        // Check proof of work (grinding to find a number that hashes to have
        // `self.config.proof_of_work_bits` zeroes at the beginning).
        if !challenger.check_witness(self.fri_config.proof_of_work_bits, proof.pow_witness) {
            return Err(BaseFoldVerifierError::Pow);
        }

        let log_len = proof.fri_commitments.len();

        if log_len + self.fri_config.log_blowup() > GC::F::TWO_ADICITY {
            return Err(BaseFoldVerifierError::TwoAdicityOverflow);
        }

        // Sample query indices for the FRI query IOPP part of BaseFold. This part is very similar
        // to the corresponding part in the univariate FRI verifier.
        let query_indices = (0..self.fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_len + self.fri_config.log_blowup()))
            .collect::<Vec<_>>();

        // Shape-check and verify Merkle openings for each committed polynomial
        let log_tensor_height = log_len + self.fri_config.log_blowup();
        for (opening_and_proof, commitment) in
            proof.component_polynomials_query_openings_and_proofs.iter().zip_eq(commitments)
        {
            let initial_opening_values = &opening_and_proof.values;
            if initial_opening_values.dimensions.sizes().len() != 2 {
                return Err(BaseFoldVerifierError::IncorrectShape);
            }
            if initial_opening_values.dimensions.sizes()[0] != query_indices.len() {
                return Err(BaseFoldVerifierError::IncorrectShape);
            }
            if opening_and_proof.proof.log_tensor_height != log_tensor_height {
                return Err(BaseFoldVerifierError::IncorrectShape);
            }

            self.tcs
                .verify_tensor_openings(
                    commitment,
                    &query_indices,
                    &opening_and_proof.values,
                    initial_opening_values.sizes()[1],
                    log_tensor_height,
                    &opening_and_proof.proof,
                )
                .map_err(BaseFoldVerifierError::TcsError)?;
        }

        // Turn the (now Merkle-verified) per-commitment openings into virtual oracle values. For
        // each query we gather the opened values into a [`Rounds`] (one round per commitment, in
        // commitment order) and ask the evaluator for the value of the virtual oracle at that
        // query's index. The Merkle proofs have already been checked above, so the evaluator only
        // ever sees field values.
        let virtual_oracle_evals = query_indices
            .iter()
            .enumerate()
            .map(|(q, &query_idx)| {
                let leaf_values = proof
                    .component_polynomials_query_openings_and_proofs
                    .iter()
                    .map(|opening| {
                        let width = opening.values.sizes()[1];
                        &opening.values.as_slice()[q * width..(q + 1) * width]
                    })
                    .collect::<Rounds<&[GC::F]>>();
                oracle_evaluator.evaluate_oracle(leaf_values, query_idx)
            })
            .collect::<Vec<_>>();

        // Check that the query openings are consistent as FRI messages.
        self.verify_queries(
            &proof.fri_commitments,
            &query_indices,
            proof.final_poly,
            virtual_oracle_evals,
            &proof.query_phase_openings_and_proofs,
            &betas,
        )?;

        // The final consistency check between the FRI messages and the partial evaluation messages.
        if proof.final_poly
            != proof.univariate_messages.last().unwrap()[0]
                + *betas.last().unwrap() * proof.univariate_messages.last().unwrap()[1]
        {
            return Err(BaseFoldVerifierError::SumcheckFinalPolyMismatch);
        }

        Ok(())
    }

    /// The FRI verifier for a single query. We modify this from Plonky3 to be compatible with
    /// opening only a single vector.
    fn verify_queries(
        &self,
        commitments: &[GC::Digest],
        indices: &[usize],
        final_poly: GC::EF,
        reduced_openings: Vec<GC::EF>,
        query_openings: &[MerkleTreeOpeningAndProof<GC>],
        betas: &[GC::EF],
    ) -> Result<(), BaseFoldVerifierError<MerkleTreeTcsError>> {
        let log_max_height = commitments.len() + self.fri_config.log_blowup();

        let mut folded_evals = reduced_openings;
        let mut indices = indices.to_vec();

        let mut xis = indices
            .iter()
            .map(|index| {
                GC::F::two_adic_generator(log_max_height)
                    .exp_u64(reverse_bits_len(*index, log_max_height) as u64)
            })
            .collect::<Vec<_>>();

        if commitments.len() != query_openings.len() || commitments.len() != betas.len() {
            return Err(BaseFoldVerifierError::IncorrectShape);
        }

        // Loop over the FRI queries.
        for (round_idx, ((commitment, query_opening), beta)) in (self.fri_config.log_blowup()
            ..log_max_height)
            .rev()
            .zip_eq(commitments.iter().zip_eq(query_openings.iter()).zip_eq(betas))
        {
            let openings = &query_opening.values;
            if openings.dimensions.sizes().len() != 2 {
                return Err(BaseFoldVerifierError::IncorrectShape);
            }

            if indices.len() != folded_evals.len()
                || indices.len() != openings.dimensions.sizes()[0]
                || indices.len() != xis.len()
            {
                return Err(BaseFoldVerifierError::IncorrectShape);
            }

            for (((index, folded_eval), opening), x) in indices
                .iter_mut()
                .zip_eq(folded_evals.iter_mut())
                .zip_eq(openings.split())
                .zip_eq(xis.iter_mut())
            {
                let index_sibling = *index ^ 1;
                let index_pair = *index >> 1;

                if opening.total_len() != 2 * <GC::EF as AbstractExtensionField<GC::F>>::D {
                    return Err(BaseFoldVerifierError::IncorrectShape);
                }

                let evals: [GC::EF; 2] = opening
                    .as_slice()
                    .chunks_exact(GC::EF::D)
                    .map(GC::EF::from_base_slice)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                // Check that the folded evaluation is consistent with the FRI query proof opening.
                if evals[*index % 2] != *folded_eval {
                    return Err(BaseFoldVerifierError::QueryValueMismatch);
                }

                let mut xs = [*x; 2];
                xs[index_sibling % 2] *= GC::F::two_adic_generator(1);

                // interpolate and evaluate at beta
                *folded_eval = evals[0]
                    + (*beta - xs[0]) * (evals[1] - evals[0]) / GC::EF::from(xs[1] - xs[0]);

                *index = index_pair;
                *x = x.square();
            }

            // Check that the opening is consistent with the commitment.
            // The magic constant 2 here is the folding factor we use for FRI.
            self.tcs
                .verify_tensor_openings(
                    commitment,
                    &indices,
                    &query_opening.values,
                    GC::EF::D * 2,
                    round_idx,
                    &query_opening.proof,
                )
                .map_err(BaseFoldVerifierError::TcsError)?;
        }

        for folded_eval in folded_evals {
            if folded_eval != final_poly {
                return Err(BaseFoldVerifierError::QueryFinalPolyMismatch);
            }
        }

        Ok(())
    }
}

/// A [`StackedPcsVerifier`] is a [`BatchPcsVerifier`]: a Basefold verifier pinned to a fixed
/// message size (`num_encoding_variables = log_stacking_height`). The opening protocol itself is
/// plain prebatched Basefold; the stacking height fixes how long the MLEs behind the commitments
/// are allowed to be, i.e. the dimension of the reduced point the committed oracles open at.
///
/// This is a temporary connector until stacked is refactored based on the new basefold API.
impl<GC: IopCtx> BatchPcsVerifier<GC> for BasefoldVerifier<GC>
where
    GC::F: TwoAdicField,
{
    type Proof = BasefoldProof<GC>;
    type VerifierError = BaseFoldVerifierError<MerkleTreeTcsError>;

    fn num_expected_commitments(&self) -> usize {
        self.num_expected_commitments
    }

    fn num_queries(&self) -> usize {
        self.fri_config.num_queries
    }

    fn num_encoding_variables(&self) -> u32 {
        self.num_encoding_variables
    }

    fn log_blowup(&self) -> usize {
        self.fri_config.log_blowup
    }

    fn verify(
        &self,
        commits: &[GC::Digest],
        reduced_point: &Point<GC::EF>,
        reduced_eval: GC::EF,
        oracle_evaluator: impl OracleEval<GC::F, GC::EF>,
        proof: &Self::Proof,
        challenger: &mut GC::Challenger,
    ) -> Result<(), Self::VerifierError> {
        self.verify_from_prebatched_inputs(
            commits,
            reduced_point.clone(),
            reduced_eval,
            proof,
            oracle_evaluator,
            challenger,
        )
    }
}
