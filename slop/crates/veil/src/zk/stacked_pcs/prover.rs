// ZK Stacked PCS Prover implementation
use crate::zk::inner::{
    MerkleProverData, PcsEvalClaim, ProverValue, ZkIopCtx, ZkMerkleizer, ZkPcsCommitmentError,
    ZkPcsProver, ZkProtocolProof, ZkProverContext,
};
use derive_where::derive_where;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractExtensionField;
use slop_alloc::CpuBackend;
use slop_basefold::BasefoldProof;
use slop_basefold_prover::{BaseFoldConfigProverError, BasefoldProverData};
use slop_challenger::FieldChallenger;
use slop_commit::Message;
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{Mle, Point};
use slop_tensor::Tensor;
use std::{fmt::Debug, iter::repeat_with, marker::PhantomData};
use thiserror::Error;

use rayon::prelude::*;

use super::{basefold_prover_wrapper::ZkBasefoldProver, ZkStackedPcsConstraintData};
use crate::zk::prover_ctx::{PcsProverConfig, ZkProverCtx};

/// Type alias for `ProverValue` when using the ZK PCS (stacked PCS).
///
/// This is the expression index type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK PCS prover context.
#[allow(type_alias_bounds)]
pub type StackedPcsProverValue<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ProverValue<GC, MK, ZkStackedPcsProverData<GC, MK>>;

/// Type alias for `ZkProverContext` when using the ZK PCS (stacked PCS).
///
/// This is the prover context type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK PCS.
#[allow(type_alias_bounds)]
pub type StackedPcsZkProverContext<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>;

/// Configuration type that implements `PcsProverConfig` for the stacked PCS.
pub struct StackedPcsProverConfig<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    _phantom: PhantomData<(GC, MK)>,
}

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>, MK: ZkMerkleizer<GC>> PcsProverConfig<GC>
    for StackedPcsProverConfig<GC, MK>
{
    type Merkelizer = MK;
    type PcsProverData = ZkStackedPcsProverData<GC, MK>;
    type PcsProver = ZkBasefoldProver<GC, MK>;
}

/// Type alias for `ZkProverCtx` when using the stacked PCS.
#[allow(type_alias_bounds)]
pub type StackedPcsZkProverCtx<
    GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>,
    MK: ZkMerkleizer<GC>,
> = ZkProverCtx<GC, StackedPcsProverConfig<GC, MK>>;

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>, MK: ZkMerkleizer<GC>>
    ZkProverCtx<GC, StackedPcsProverConfig<GC, MK>>
{
    /// Initializes a prover context with stacked PCS support.
    pub fn initialize_with_pcs<RNG: rand::CryptoRng + rand::Rng>(
        mask_length: usize,
        pcs_prover: ZkBasefoldProver<GC, MK>,
        rng: &mut RNG,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self::initialize(mask_length, rng, Some(pcs_prover))
    }

    /// Initializes a linear-only prover context with stacked PCS support.
    pub fn initialize_with_pcs_only_lin<RNG: rand::CryptoRng + rand::Rng>(
        mask_length: usize,
        pcs_prover: ZkBasefoldProver<GC, MK>,
        rng: &mut RNG,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self::initialize_only_lin_constraints(mask_length, rng, Some(pcs_prover))
    }
}

#[derive(Debug)]
#[derive_where(Clone; MerkleProverData<GC, MK>: Clone)]
#[derive_where(Serialize, Deserialize; MerkleProverData<GC, MK>, Tensor<GC::F, CpuBackend>)]
pub struct ZkStackedPcsProverData<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    pub full_pcs_data: BasefoldProverData<GC::F, MerkleProverData<GC, MK>>,
    pub mles: Message<Mle<GC::F, CpuBackend>>,
    pub mle_num_vars: usize,
}

#[derive(Error, Debug)]
pub enum ZkStackedPcsProverError<E> {
    #[error("Basefold prover error: {0}")]
    BasefoldError(E),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct ZkStackedPcsProof<GC: ZkIopCtx> {
    /// Basefold proof for the RLC polynomial evaluation
    pub rlc_eval_proof: BasefoldProof<GC>,
    /// RLC evaluation claim (a_q in the protocol)
    pub rlc_eval_claim: GC::EF,
    /// RLC padding vector
    pub rlc_padding_vec: Vec<GC::EF>,
    /// The number of MLEs stacked together
    pub log_num_polys: usize,
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkBasefoldProver<GC, MK> {
    /// Takes in a batch of MLE's and commits it in a zk-way
    /// The last "padding" entries of each MLE are the padding
    #[allow(clippy::type_complexity)]
    pub fn zk_commit_mles<RNG: rand::CryptoRng + rand::Rng>(
        &self,
        mle: Mle<GC::F, CpuBackend>,
        rng: &mut RNG,
    ) -> Result<
        (GC::Digest, ZkStackedPcsProverData<GC, MK>),
        ZkStackedPcsProverError<BaseFoldConfigProverError<GC, MK>>,
    >
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let log_num_polys = mle.num_polynomials().next_power_of_two().trailing_zeros();
        let mle_num_vars = mle.num_variables() as usize;
        let num_data_cols = 1usize << log_num_polys;
        let num_mask_cols = GC::EF::D;
        let num_cols = num_data_cols + num_mask_cols;
        let num_data_rows = 1usize << mle_num_vars;

        // Get padding amount from FRI config
        let query_count = self.inner.encoder.config().num_queries;
        let num_rows = num_data_rows + query_count;

        // Pre-generate random masking and padding using the provided RNG
        let masking_mle: Vec<GC::F> =
            repeat_with(|| rng.gen()).take(num_data_rows * num_mask_cols).collect();
        let padding: Vec<GC::F> = repeat_with(|| rng.gen()).take(query_count * num_cols).collect();

        // Build the interleaved matrix directly: [data_cols | mask_cols] per row,
        // followed by padding rows.
        let mle_vec = mle.into_guts().into_buffer().into_vec();
        let total_len = num_rows * num_cols;
        let mut all_mle_vec = Vec::with_capacity(total_len);
        for i in 0..num_data_rows {
            all_mle_vec.extend_from_slice(&mle_vec[i * num_data_cols..(i + 1) * num_data_cols]);
            all_mle_vec.extend_from_slice(&masking_mle[i * num_mask_cols..(i + 1) * num_mask_cols]);
        }
        all_mle_vec.extend_from_slice(&padding);

        let all_mle: Message<_> =
            Mle::new(RowMajorMatrix::new(all_mle_vec, num_cols).into()).into();

        // commit all MLEs
        let (commit, full_pcs_data) = self
            .commit_padded_multilinears(all_mle.clone())
            .map_err(ZkStackedPcsProverError::BasefoldError)?;

        let prover_data = ZkStackedPcsProverData { full_pcs_data, mles: all_mle, mle_num_vars };

        Ok((commit, prover_data))
    }

    /// Generate an evaluation proof for a single claim on one committed MLE.
    ///
    /// Returns a tuple of:
    /// - `ZkStackedPcsProof`: The proof data to send to verifier
    /// - `ZkStackedPcsConstraintData`: Constraint data which will be recomputed by verifier
    #[allow(clippy::type_complexity)]
    pub fn zk_generate_eval_proof_for_mle(
        &self,
        prover_data: ZkStackedPcsProverData<GC, MK>,
        eval_point: &Point<GC::EF>,
        eval_claim: &StackedPcsProverValue<GC, MK>,
        zkbuilder: &mut ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>,
    ) -> Result<
        (
            ZkStackedPcsProof<GC>,
            ZkStackedPcsConstraintData<GC, ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>>,
        ),
        ZkStackedPcsProverError<BaseFoldConfigProverError<GC, MK>>,
    > {
        // Deconstruct prover_data
        let ZkStackedPcsProverData { full_pcs_data, mles, mle_num_vars } = prover_data;

        let log_num_polys =
            (mles[0].num_polynomials() - GC::EF::D).next_power_of_two().trailing_zeros() as usize; // -deg(EF/F) for mask

        // Step 1: Evaluate all rows at the inner point and add to transcript
        let (eval_point_inner, _) = eval_point.split_at(eval_point.dimension() - log_num_polys);
        let evals = mles[0].eval_at(&eval_point_inner);
        let evals_elts = zkbuilder.add_values(evals.evaluations().as_slice());
        let evals_slice = evals.into_evaluations().into_buffer().into_vec();

        // Step 2: Sample RLC point (dimension = log_num_polys) and RLC coefficient
        let rlc_point = {
            let mut challenger = zkbuilder.challenger();
            let coords: Vec<GC::EF> =
                (0..log_num_polys).map(|_| challenger.sample_ext_element()).collect();
            Point::new(coords.into())
        };
        // Step 3: Compute RLC multilinear using eq-based coefficients and add mask terms
        // Note the conversion from GC::EF::D base field to an extension field element
        let eq_evals = Mle::partial_lagrange(&rlc_point);
        let num_original = 1 << log_num_polys;
        let to_dot_tensor = mles[0].guts();
        let mut rlc_mle_vec = Vec::with_capacity(to_dot_tensor.total_len());
        to_dot_tensor
            .as_buffer()
            .par_chunks_exact(to_dot_tensor.strides()[0])
            .map(|chunk| {
                let eq_sum: GC::EF = eq_evals
                    .guts()
                    .as_buffer()
                    .iter()
                    .zip_eq(chunk[..num_original].iter())
                    .map(|(eq, &b)| *eq * GC::EF::from(b))
                    .sum();
                eq_sum + GC::EF::from_base_slice(&chunk[num_original..])
            })
            .collect_into_vec(&mut rlc_mle_vec);

        // Step 4: Commit the unpadded RLC MLE and split off padding
        let unpadded_mle_length: usize = 1 << mle_num_vars;
        let rlc_padding_vec = rlc_mle_vec.split_off(unpadded_mle_length);
        let rlc_mle_vec = rlc_mle_vec;

        // Find the codeword for the RLC MLE
        let batch_mle_f = RowMajorMatrix::new(rlc_mle_vec.clone(), 1).flatten_to_base::<GC::F>();
        let batch_mle_f = Tensor::from(batch_mle_f).reshape([1 << mle_num_vars, GC::EF::D]);
        let rlc_codeword =
            self.inner.encoder.encode_batch(Message::from(Mle::new(batch_mle_f))).unwrap();
        let rlc_codeword = (*rlc_codeword[0]).clone();

        // Step 5: Compute a_q = RLC eval at the inner point
        let eq_sum: GC::EF = eq_evals
            .guts()
            .as_slice()
            .iter()
            .zip_eq(evals_slice[..num_original].iter())
            .map(|(eq_val, &eval)| *eq_val * eval)
            .sum();
        let mask_sum: GC::EF =
            (0..GC::EF::D).map(|i| GC::EF::monomial(i) * evals_slice[num_original + i]).sum();
        let rlc_eval_claim = eq_sum + mask_sum;

        // Step 6: Observe RLC padding and eval claim
        {
            let mut challenger = zkbuilder.challenger();
            challenger.observe_ext_element_slice(&rlc_padding_vec[..]);
            challenger.observe_ext_element(rlc_eval_claim);
        }

        // Step 7: Prove basefold evaluation r(x^{(2)}) = a_q
        let rlc_mle_extension = Mle::new(RowMajorMatrix::new(rlc_mle_vec, 1).into());
        let rlc_eval_proof = {
            let mut challenger = zkbuilder.challenger();
            self.prove_with_batched_ef_inputs(
                eval_point_inner,
                rlc_mle_extension,
                rlc_codeword,
                rlc_eval_claim,
                full_pcs_data,
                &mut challenger,
            )
            .map_err(ZkStackedPcsProverError::BasefoldError)?
        };

        // Build constraint data (shared with verifier)
        let claim_data = super::ZkStackedPcsClaimData {
            point: eval_point.clone(),
            orig_eval_index: eval_claim.clone(),
            rlc_eval_claim,
            evals: evals_elts,
        };

        let constraint_data = ZkStackedPcsConstraintData {
            log_num_cols: log_num_polys,
            rlc_point,
            claim: claim_data,
        };

        let proof =
            ZkStackedPcsProof { rlc_eval_proof, rlc_eval_claim, rlc_padding_vec, log_num_polys };

        Ok((proof, constraint_data))
    }
}

// ============================================================================
// ZkPcsProver trait implementation
// ============================================================================

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>, MK: ZkMerkleizer<GC>> ZkPcsProver<GC, MK>
    for ZkBasefoldProver<GC, MK>
{
    type ProverData = ZkStackedPcsProverData<GC, MK>;

    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &self,
        mle: Mle<GC::F, CpuBackend>,
        log_stacking_height: usize,
        rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        // Stack the flat MLE into a multi-row form
        let stacked_mle = super::utils::stack_mle(mle, log_stacking_height);

        // Generate the commitment
        let (digest, prover_data) = self
            .zk_commit_mles(stacked_mle, rng)
            .map_err(|e| ZkPcsCommitmentError::CommitmentFailed(e.to_string()))?;

        Ok((digest, prover_data))
    }

    fn prove_eval(
        &self,
        ctx: &mut ZkProverContext<GC, MK, Self::ProverData>,
        claim: PcsEvalClaim<GC::EF, ProverValue<GC, MK, Self::ProverData>>,
    ) -> GC::PcsProof {
        let commitment_index = claim.commitment_index;

        // Look up the prover data from context using the commitment index
        let prover_data = ctx
            .get_prover_data(commitment_index)
            .expect("prove_evals called with invalid commitment index");

        // Generate the proof and constraint data
        let (proof, constraint_data) = self
            .zk_generate_eval_proof_for_mle(prover_data, &claim.point, &claim.eval_expr, ctx)
            .expect("Failed to generate ZK stacked PCS proof");

        // Build the constraints from the constraint data
        constraint_data.build_constraints();

        proof
    }
}
