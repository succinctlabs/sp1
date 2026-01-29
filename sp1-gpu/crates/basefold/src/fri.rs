use itertools::Itertools;
use std::{marker::PhantomData, sync::Arc};

use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, TwoAdicField};
use slop_alloc::{Buffer, HasBackend};
use slop_basefold::{BasefoldProof, FriConfig};
use slop_basefold_prover::{host_fold_even_odd, BasefoldProverError};
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_merkle_tree::MerkleTreeOpeningAndProof;
use slop_multilinear::{Evaluations, Mle, MleEval, Point};
use slop_tensor::Tensor;
use sp1_primitives::{SP1ExtensionField, SP1Field};

use sp1_gpu_cudart::{
    args,
    sys::{
        basefold::{
            batch_koala_bear_base_ext_kernel, batch_koala_bear_base_ext_kernel_flattened,
            flatten_to_base_koala_bear_base_ext_kernel,
            transpose_even_odd_koala_bear_base_ext_kernel,
        },
        runtime::KernelPtr,
    },
    DeviceBuffer, DeviceMle, DeviceTensor, TaskScope,
};
use sp1_gpu_merkle_tree::{CudaTcsProver, MerkleTreeProverData, SingleLayerMerkleTreeProverError};
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle, TraceDenseData};

use crate::{
    encode_batch, CudaStackedPcsProverData, DeviceGrindingChallenger, GrindingPowCudaProver,
    SpparkDftKoalaBear,
};

/// # Safety
///
pub unsafe trait MleBatchKernel<F: TwoAdicField, EF: ExtensionField<F>> {
    fn batch_mle_kernel() -> KernelPtr;
}

/// # Safety
///
pub unsafe trait RsCodeWordBatchKernel<F: TwoAdicField, EF: ExtensionField<F>> {
    fn batch_rs_codeword_kernel() -> KernelPtr;
}

/// # Safety
pub unsafe trait RsCodeWordTransposeKernel<F: TwoAdicField, EF: ExtensionField<F>> {
    fn transpose_even_odd_kernel() -> KernelPtr;
}

/// # Safety
pub unsafe trait MleFlattenKernel<F: TwoAdicField, EF: ExtensionField<F>> {
    fn flatten_to_base_kernel() -> KernelPtr;
}

pub struct FriCudaProver<GC, P, F> {
    pub tcs_prover: P,
    pub config: FriConfig<F>,
    pub log_height: u32,
    _marker: PhantomData<GC>,
}

impl<GC: IopCtx<F = Felt, EF = Ext>, P> FriCudaProver<GC, P, GC::F>
where
    GC::F: TwoAdicField,
    GC::EF: ExtensionField<GC::F> + TwoAdicField,
    P: CudaTcsProver<GC>,

    TaskScope: MleBatchKernel<GC::F, GC::EF>
        + RsCodeWordBatchKernel<GC::F, GC::EF>
        + RsCodeWordTransposeKernel<GC::F, GC::EF>
        + MleFlattenKernel<GC::F, GC::EF>,
{
    pub fn new(tcs_prover: P, config: FriConfig<GC::F>, log_height: u32) -> Self {
        Self { tcs_prover, config, log_height, _marker: PhantomData }
    }
    pub fn encode_and_commit(
        &self,
        use_preprocessed: bool,
        drop_traces: bool,
        jagged_trace_mle: &JaggedTraceMle<Felt, TaskScope>,
        mut dst: Tensor<Felt, TaskScope>,
    ) -> Result<
        (<GC as IopCtx>::Digest, CudaStackedPcsProverData<GC>),
        SingleLayerMerkleTreeProverError,
    > {
        let encoder = SpparkDftKoalaBear::default();

        unsafe {
            dst.assume_init();
        }

        let virtual_tensor = if use_preprocessed {
            jagged_trace_mle.preprocessed_virtual_tensor(self.log_height)
        } else {
            jagged_trace_mle.main_virtual_tensor(self.log_height)
        };

        encode_batch(encoder, self.config.log_blowup as u32, virtual_tensor, &mut dst).unwrap();

        // Commit to the tensors.

        let (commitment, tcs_data) = self.tcs_prover.commit_tensors(&dst)?;

        let codeword_mle = if drop_traces { None } else { Some(Arc::new(dst)) };
        let prover_data = CudaStackedPcsProverData { merkle_tree_tcs_data: tcs_data, codeword_mle };

        Ok((commitment, prover_data))
    }

    #[allow(clippy::type_complexity)]
    pub fn batch(
        &self,
        batching_challenge: GC::EF,
        mles: &TraceDenseData<GC::F, TaskScope>,
        codewords: Message<Tensor<Felt, TaskScope>>,
        evaluation_claims: Vec<MleEval<GC::EF, TaskScope>>,
    ) -> (Mle<GC::EF, TaskScope>, Tensor<GC::F, TaskScope>, GC::EF) {
        let log_stacking_height = self.log_height;
        // Compute all the batch challenge powers.
        let total_num_polynomials = codewords.iter().map(|c| c.sizes()[0]).sum::<usize>();

        let mut batch_challenge_powers =
            batching_challenge.powers().take(total_num_polynomials).collect::<Vec<_>>();

        // Compute the random linear combination of the MLEs of the columns of the matrices
        let num_variables = log_stacking_height;
        let codeword_size = (codewords.first().unwrap()).sizes()[1];
        let scope: TaskScope = mles.backend().clone();
        let mut batch_mle =
            Mle::new(Tensor::<GC::EF, TaskScope>::zeros_in([1, 1 << num_variables], scope.clone()));
        let mut batch_codeword = Tensor::<GC::F, TaskScope>::zeros_in(
            [<GC::EF as AbstractExtensionField<GC::F>>::D, codeword_size],
            scope.clone(),
        );

        unsafe {
            let block_dim = 256;
            let grid_dim = (1usize << num_variables).div_ceil(block_dim);
            let batch_size = total_num_polynomials;
            let powers_device =
                DeviceBuffer::from_host(&Buffer::from(batch_challenge_powers.clone()), &scope)
                    .unwrap()
                    .into_inner();
            let mle_args = args!(
                mles.dense.as_ptr(),
                batch_mle.guts_mut().as_mut_ptr(),
                powers_device.as_ptr(),
                (1 << num_variables) as usize,
                batch_size
            );
            scope
                .launch_kernel(TaskScope::batch_mle_kernel(), grid_dim, block_dim, &mle_args, 0)
                .unwrap();
        }

        for codeword in codewords.iter() {
            let batch_size = codeword.sizes()[0];
            let mut powers = batch_challenge_powers;
            batch_challenge_powers = powers.split_off(batch_size);
            let powers_device = DeviceBuffer::from_host(&Buffer::from(powers.clone()), &scope)
                .unwrap()
                .into_inner();

            let block_dim = 256;
            let grid_dim = codeword_size.div_ceil(block_dim);
            let codeword_args = args!(
                codeword.as_ptr(),
                batch_codeword.as_mut_ptr(),
                powers_device.as_ptr(),
                codeword_size,
                batch_size
            );
            unsafe {
                scope
                    .launch_kernel(
                        TaskScope::batch_rs_codeword_kernel(),
                        grid_dim,
                        block_dim,
                        &codeword_args,
                        0,
                    )
                    .unwrap();
            }
        }

        // Compute the batched evaluation claim.
        let mut batch_eval_claim = GC::EF::zero();
        let mut power = GC::EF::one();
        for batch_claims in evaluation_claims {
            let claims = DeviceTensor::from_raw(batch_claims.into_evaluations()).to_host().unwrap();
            for value in claims.as_slice() {
                batch_eval_claim += power * *value;
                power *= batching_challenge;
            }
        }

        (batch_mle, batch_codeword, batch_eval_claim)
    }

    #[allow(clippy::type_complexity)]
    fn commit_phase_round(
        &self,
        current_mle: Mle<GC::EF, TaskScope>,
        current_codeword: Tensor<GC::F, TaskScope>,
        challenger: &mut GC::Challenger,
    ) -> Result<
        (
            GC::EF,
            Mle<GC::EF, TaskScope>,
            Tensor<GC::F, TaskScope>,
            GC::Digest,
            Tensor<GC::F, TaskScope>,
            MerkleTreeProverData<GC::Digest>,
        ),
        SingleLayerMerkleTreeProverError,
    > {
        // Perform a single round of the FRI commit phase, returning the commitment, folded
        // codeword, and folding parameter.
        // On CPU, the current codeword is in row-major form, which means that in order to put
        // even and odd entries together all we need to do is rehsape it to multiply the number of
        // columns by 2 and divide the number of rows by 2.
        let codeword_size = current_codeword.sizes()[1];
        let batch_size = current_codeword.sizes()[0];
        let scope = current_codeword.backend().clone();

        let mut leaves = Tensor::with_sizes_in([batch_size * 2, codeword_size / 2], scope.clone());
        let output_codeword_size = codeword_size / 2;
        let block_dim = 256;
        let grid_dim = output_codeword_size.div_ceil(block_dim);
        unsafe {
            let args = args!(current_codeword.as_ptr(), leaves.as_mut_ptr(), output_codeword_size);
            leaves.assume_init();
            scope
                .launch_kernel(
                    TaskScope::transpose_even_odd_kernel(),
                    grid_dim,
                    block_dim,
                    &args,
                    0,
                )
                .unwrap();
        }

        let (commit, prover_data) = self.tcs_prover.commit_tensors(&leaves)?;
        // Observe the commitment.
        challenger.observe(commit);

        let beta: GC::EF = challenger.sample_ext_element();

        // Fold the mle.
        let folded_mle: Mle<_, TaskScope> = {
            let device_mle = DeviceMle::from(current_mle);
            device_mle.fold(beta).into()
        };
        let folded_num_variables = folded_mle.num_variables();

        if folded_num_variables < 4 {
            let current_codeword_transposed =
                DeviceTensor::from_raw(current_codeword.clone()).transpose();
            let current_codeword_vec = current_codeword_transposed.to_host().unwrap();
            let current_codeword_vec =
                current_codeword_vec.into_buffer().into_extension::<GC::EF>().into_vec();
            let folded_codeword_vec = host_fold_even_odd(current_codeword_vec, beta);
            let folded_codeword_storage =
                Buffer::from(folded_codeword_vec).flatten_to_base::<GC::F>();
            let mut new_size = current_codeword.sizes().to_vec();
            new_size[1] /= 2;
            let folded_codeword =
                DeviceBuffer::from_host(&folded_codeword_storage, folded_mle.backend())
                    .unwrap()
                    .into_inner();
            let folded_codeword = Tensor::from(folded_codeword).reshape([new_size[1], new_size[0]]);
            let folded_codeword = DeviceTensor::from_raw(folded_codeword).transpose().into_inner();
            return Ok((beta, folded_mle, folded_codeword, commit, leaves, prover_data));
        }

        let folded_height = 1 << folded_num_variables;
        let mut folded_mle_flattened = Tensor::<GC::F, TaskScope>::with_sizes_in(
            [<GC::EF as AbstractExtensionField<GC::F>>::D, folded_height],
            scope.clone(),
        );

        let mut folded_codeword = Tensor::<GC::F, TaskScope>::zeros_in(
            [<GC::EF as AbstractExtensionField<GC::F>>::D, folded_height << self.config.log_blowup],
            scope.clone(),
        );

        let block_dim = 256;
        let grid_dim = folded_height.div_ceil(block_dim);
        unsafe {
            let args =
                args!(folded_mle.guts().as_ptr(), folded_mle_flattened.as_mut_ptr(), folded_height);
            folded_mle_flattened.assume_init();
            scope
                .launch_kernel(TaskScope::flatten_to_base_kernel(), grid_dim, block_dim, &args, 0)
                .unwrap();
        }
        let encoder = SpparkDftKoalaBear::default();
        encode_batch(
            encoder,
            self.config.log_blowup as u32,
            folded_mle_flattened.as_view(),
            &mut folded_codeword,
        )
        .unwrap();

        Ok((beta, folded_mle, folded_codeword, commit, leaves, prover_data))
    }

    fn final_poly(&self, final_codeword: Tensor<GC::F, TaskScope>) -> GC::EF {
        let final_codeword_host = DeviceTensor::from_raw(final_codeword).to_host().unwrap();
        let final_codeword_transposed = final_codeword_host.transpose();
        GC::EF::from_base_slice(
            &final_codeword_transposed.storage.as_slice()
                [0..(<GC::EF as AbstractExtensionField<GC::F>>::D)],
        )
    }

    #[inline]
    pub fn prove_trusted_evaluations_basefold(
        &self,
        mut eval_point: Point<GC::EF>,
        evaluation_claims: Rounds<Evaluations<GC::EF, TaskScope>>,
        mles: &JaggedTraceMle<GC::F, TaskScope>,
        prover_data: Rounds<&CudaStackedPcsProverData<GC>>,
        challenger: &mut GC::Challenger,
    ) -> Result<BasefoldProof<GC>, BasefoldProverError<SingleLayerMerkleTreeProverError>>
    where
        GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
    {
        let scope = mles.dense().dense.backend().clone();
        let mut codewords: Vec<Arc<Tensor<Felt, TaskScope>>> = Vec::new();
        for data in prover_data.iter() {
            if let Some(ref codeword) = data.codeword_mle {
                codewords.push(codeword.clone());
            } else {
                // Codeword was dropped - this is always a main trace.
                let mut dst = Tensor::<Felt, TaskScope>::with_sizes_in(
                    [
                        mles.dense().main_size() >> self.log_height,
                        1 << (self.log_height as usize + self.config.log_blowup()),
                    ],
                    scope.clone(),
                );
                unsafe {
                    dst.assume_init();
                }

                let encoder = SpparkDftKoalaBear::default();
                encode_batch(
                    encoder,
                    self.config.log_blowup as u32,
                    mles.main_virtual_tensor(self.log_height),
                    &mut dst,
                )
                .unwrap();

                codewords.push(Arc::new(dst));
            }
        }

        let encoded_messages: Message<_> = codewords.iter().cloned().collect();

        let evaluation_claims = evaluation_claims.into_iter().flatten().collect::<Vec<_>>();

        // Sample a batching challenge and batch the mles and codewords.
        let batching_challenge: GC::EF = challenger.sample_ext_element();
        // Batch the mles and codewords.
        let (mle_batch, codeword_batch, batched_eval_claim) =
            self.batch(batching_challenge, mles.dense(), encoded_messages, evaluation_claims);
        // From this point on, run the BaseFold protocol on the random linear combination codeword,
        // the random linear combination multilinear, and the random linear combination of the
        // evaluation claims.
        let mut current_mle = mle_batch;
        let mut current_codeword = codeword_batch;
        // Initialize the vecs that go into a BaseFoldProof.
        let log_len = current_mle.num_variables();
        let mut univariate_messages: Vec<[GC::EF; 2]> = vec![];
        let mut fri_commitments = vec![];
        let mut commit_phase_data = vec![];
        let mut current_batched_eval_claim = batched_eval_claim;
        let mut commit_phase_values = vec![];

        assert_eq!(
            current_mle.num_variables(),
            eval_point.dimension() as u32,
            "eval point dimension mismatch"
        );

        challenger.observe(Felt::from_canonical_usize(eval_point.dimension()));
        for _ in 0..eval_point.dimension() {
            // Compute claims for `g(X_0, X_1, ..., X_{d-1}, 0)` and `g(X_0, X_1, ..., X_{d-1}, 1)`.
            let last_coord = eval_point.remove_last_coordinate();
            let zero_values = {
                use sp1_gpu_cudart::DeviceMle;
                let device_mle = DeviceMle::from(current_mle.clone());
                let evals = device_mle.fixed_at_zero(&eval_point);
                evals.to_host_vec().unwrap()
            };
            let zero_val = zero_values[0];
            let one_val = (current_batched_eval_claim - zero_val) / last_coord + zero_val;
            let uni_poly = [zero_val, one_val];
            univariate_messages.push(uni_poly);

            uni_poly.iter().for_each(|elem| challenger.observe_ext_element(*elem));

            // Perform a single round of the FRI commit phase, returning the commitment, folded
            // codeword, and folding parameter.
            let (beta, folded_mle, folded_codeword, commitment, leaves, prover_data) = self
                .commit_phase_round(current_mle, current_codeword, challenger)
                .map_err(BasefoldProverError::CommitPhaseError)?;

            fri_commitments.push(commitment);
            commit_phase_data.push(prover_data);
            commit_phase_values.push(leaves);

            current_mle = folded_mle;
            current_codeword = folded_codeword;
            current_batched_eval_claim = zero_val + beta * one_val;
        }

        let final_poly = self.final_poly(current_codeword);
        challenger.observe_ext_element(final_poly);

        let fri_config = self.config;
        let pow_bits = fri_config.proof_of_work_bits;
        let pow_witness = GrindingPowCudaProver::grind(challenger, pow_bits, &scope);
        // FRI Query Phase.
        let query_indices: Vec<usize> = (0..fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_len as usize + fri_config.log_blowup()))
            .collect();

        // Open the original polynomials at the query indices.
        let mut component_polynomials_query_openings_and_proofs = vec![];
        for (data, codeword) in prover_data.iter().zip(codewords.iter()) {
            let values = self.tcs_prover.compute_openings_at_indices(codeword, &query_indices);
            let proof = self
                .tcs_prover
                .prove_openings_at_indices(&data.merkle_tree_tcs_data, &query_indices)
                .map_err(BasefoldProverError::TcsCommitError)?;
            let opening = MerkleTreeOpeningAndProof::<GC> { values, proof };
            component_polynomials_query_openings_and_proofs.push(opening);
        }

        // Provide openings for the FRI query phase.
        let mut query_phase_openings_and_proofs = vec![];
        let mut indices = query_indices;
        for (leaves, data) in commit_phase_values.into_iter().zip_eq(commit_phase_data) {
            for index in indices.iter_mut() {
                *index >>= 1;
            }
            let values = self.tcs_prover.compute_openings_at_indices(&leaves, &indices);

            let proof = self
                .tcs_prover
                .prove_openings_at_indices(&data, &indices)
                .map_err(BasefoldProverError::TcsCommitError)?;
            let opening = MerkleTreeOpeningAndProof { values, proof };
            query_phase_openings_and_proofs.push(opening);
        }

        Ok(BasefoldProof {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings_and_proofs,
            query_phase_openings_and_proofs,
            final_poly,
            pow_witness,
        })
    }
}

unsafe impl MleBatchKernel<SP1Field, SP1ExtensionField> for TaskScope {
    fn batch_mle_kernel() -> KernelPtr {
        unsafe { batch_koala_bear_base_ext_kernel() }
    }
}

unsafe impl RsCodeWordBatchKernel<SP1Field, SP1ExtensionField> for TaskScope {
    fn batch_rs_codeword_kernel() -> KernelPtr {
        unsafe { batch_koala_bear_base_ext_kernel_flattened() }
    }
}

unsafe impl RsCodeWordTransposeKernel<SP1Field, SP1ExtensionField> for TaskScope {
    fn transpose_even_odd_kernel() -> KernelPtr {
        unsafe { transpose_even_odd_koala_bear_base_ext_kernel() }
    }
}

unsafe impl MleFlattenKernel<SP1Field, SP1ExtensionField> for TaskScope {
    fn flatten_to_base_kernel() -> KernelPtr {
        unsafe { flatten_to_base_koala_bear_base_ext_kernel() }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slop_alloc::{CpuBackend, ToHost};
    use slop_basefold::BasefoldVerifier;
    use slop_basefold_prover::BasefoldProver;
    use slop_commit::Message;
    use slop_futures::queue::WorkerQueue;
    use slop_merkle_tree::Poseidon2KoalaBear16Prover;
    use slop_multilinear::Mle;
    use slop_stacked::interleave_multilinears_with_fixed_rate;
    use sp1_gpu_cudart::{run_sync_in_place, DeviceTensor, PinnedBuffer};
    use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
    use sp1_gpu_tracegen::CudaTraceGenerator;
    use sp1_hypercube::prover::{ProverSemaphore, TraceGenerator};

    use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
        self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
    };
    use sp1_gpu_jagged_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
    use sp1_gpu_utils::{Ext, Felt, TestGC};
    use sp1_primitives::fri_params::core_fri_config;
    use sp1_primitives::SP1GlobalContext;

    use super::*;

    #[test]
    fn test_basefold() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (machine, record, program) = rt.block_on(tracegen_setup::setup());

        run_sync_in_place(|scope| {
            let verifier = BasefoldVerifier::<SP1GlobalContext>::new(core_fri_config(), 2);
            let old_prover =
                BasefoldProver::<SP1GlobalContext, Poseidon2KoalaBear16Prover>::new(&verifier);

            let new_cuda_prover = FriCudaProver::<TestGC, _, Felt> {
                tcs_prover: Poseidon2SP1Field16CudaProver::new(&scope),
                config: verifier.fri_config,
                log_height: LOG_STACKING_HEIGHT,
                _marker: PhantomData::<TestGC>,
            };

            // Generate traces using the host tracegen.
            let semaphore = ProverSemaphore::new(1);
            let trace_generator = CudaTraceGenerator::new_in(machine.clone(), scope.clone());
            let old_traces = rt.block_on(trace_generator.generate_traces(
                program.clone(),
                record.clone(),
                CORE_MAX_LOG_ROW_COUNT as usize,
                semaphore.clone(),
            ));

            let preprocessed_traces = old_traces.preprocessed_traces.clone();

            let message = preprocessed_traces
                .into_iter()
                .filter_map(|mle| mle.1.into_inner())
                .map(|x| Clone::clone(x.as_ref()))
                .collect::<Message<Mle<_, _>>>();

            let host_message: Message<_> = message
                .clone()
                .into_iter()
                .map(|mle| {
                    let mle = Arc::unwrap_or_clone(mle);
                    let guts = mle.into_guts();
                    let device_mle = sp1_gpu_cudart::DeviceMle::from(guts);
                    device_mle.to_host().unwrap()
                })
                .collect();

            let interleaved_message =
                interleave_multilinears_with_fixed_rate(32, host_message, LOG_STACKING_HEIGHT);

            let interleaved_message =
                interleaved_message.into_iter().map(|x| x.as_ref().clone()).collect::<Message<_>>();

            let (old_preprocessed_commitment, old_preprocessed_prover_data) =
                old_prover.commit_mles(interleaved_message.clone()).unwrap();

            let new_semaphore = ProverSemaphore::new(1);
            let capacity = CORE_MAX_TRACE_SIZE as usize;
            let buffer = PinnedBuffer::<Felt>::with_capacity(capacity);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = rt.block_on(queue.pop()).unwrap();
            let (_, new_traces, _, _) = rt.block_on(full_tracegen(
                &machine,
                program,
                Arc::new(record),
                &buffer,
                CORE_MAX_TRACE_SIZE as usize,
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT,
                &scope,
                new_semaphore,
                false,
            ));

            let dst = Tensor::<Felt, TaskScope>::with_sizes_in(
                [
                    new_traces.0.dense().preprocessed_offset >> LOG_STACKING_HEIGHT,
                    1 << (LOG_STACKING_HEIGHT as usize + verifier.fri_config.log_blowup()),
                ],
                scope.clone(),
            );

            let (new_preprocessed_commit, new_preprocessed_prover_data) =
                new_cuda_prover.encode_and_commit(true, false, &new_traces, dst).unwrap();

            assert_eq!(new_preprocessed_commit, old_preprocessed_commitment);

            let dst = Tensor::<Felt, TaskScope>::with_sizes_in(
                [
                    new_traces.0.dense().main_size() >> LOG_STACKING_HEIGHT,
                    1 << (LOG_STACKING_HEIGHT as usize + verifier.fri_config.log_blowup()),
                ],
                scope.clone(),
            );

            let (new_main_commit, new_main_prover_data) =
                new_cuda_prover.encode_and_commit(false, false, &new_traces, dst).unwrap();
            let message = old_traces
                .main_trace_data
                .traces
                .into_iter()
                .filter_map(|mle| mle.1.into_inner())
                .map(|x| Clone::clone(x.as_ref()))
                .collect::<Message<Mle<_, _>>>();

            let mut host_message = Vec::new();
            for mle in message.into_iter() {
                let mle = Arc::unwrap_or_clone(mle);
                let guts = mle.into_guts();
                let device_mle = sp1_gpu_cudart::DeviceMle::from(guts);
                let mle_host = device_mle.to_host().unwrap();
                host_message.push(mle_host);
            }

            let host_message = host_message.into_iter().collect::<Message<Mle<Felt, CpuBackend>>>();

            let interleaved_message_2 =
                interleave_multilinears_with_fixed_rate(32, host_message, LOG_STACKING_HEIGHT);

            let (old_main_commitment, old_main_prover_data) =
                old_prover.commit_mles(interleaved_message_2.clone()).unwrap();

            assert_eq!(new_main_commit, old_main_commitment);

            let mut rng = rand::thread_rng();

            let eval_point_host = Point::<Ext>::rand(&mut rng, LOG_STACKING_HEIGHT);

            let evaluation_claims_1: Vec<_> = interleaved_message
                .clone()
                .into_iter()
                .map(|mle| mle.eval_at(&eval_point_host))
                .collect();

            let evaluation_claims_1 = Evaluations { round_evaluations: evaluation_claims_1 };

            let evaluation_claims_2: Vec<_> = interleaved_message_2
                .clone()
                .into_iter()
                .map(|mle| mle.eval_at(&eval_point_host))
                .collect();

            let host_evaluation_claims_1: Vec<MleEval<Ext, CpuBackend>> = evaluation_claims_1
                .round_evaluations
                .iter()
                .map(|mle| mle.to_host().unwrap())
                .collect();

            let host_evaluation_claims_2: Vec<MleEval<Ext, CpuBackend>> =
                evaluation_claims_2.iter().map(|mle| mle.to_host().unwrap()).collect();

            let flattened_evaluation_claims = vec![
                MleEval::new(
                    host_evaluation_claims_1
                        .into_iter()
                        .flat_map(|x: MleEval<Ext, CpuBackend>| x.evaluations().storage.to_vec())
                        .collect(),
                ),
                MleEval::new(
                    host_evaluation_claims_2
                        .into_iter()
                        .flat_map(|x: MleEval<Ext, CpuBackend>| x.evaluations().storage.to_vec())
                        .collect(),
                ),
            ];

            let evaluation_claims_2 = Evaluations { round_evaluations: evaluation_claims_2 };

            let mut challenger = SP1GlobalContext::default_challenger();

            scope.synchronize_blocking().unwrap();
            let now = std::time::Instant::now();

            let basefold_proof = old_prover
                .prove_trusted_mle_evaluations(
                    eval_point_host.clone(),
                    vec![interleaved_message, interleaved_message_2].into_iter().collect(),
                    vec![evaluation_claims_1.clone(), evaluation_claims_2.clone()]
                        .into_iter()
                        .collect(),
                    vec![old_preprocessed_prover_data, old_main_prover_data].into_iter().collect(),
                    &mut challenger,
                )
                .unwrap();

            scope.synchronize_blocking().unwrap();
            tracing::info!("Old proof time: {:?}", now.elapsed());

            let mut challenger = SP1GlobalContext::default_challenger();

            let mut evaluation_claims_1_device = Vec::new();

            for evaluation in &evaluation_claims_1.round_evaluations {
                let eval_device =
                    DeviceTensor::from_host(evaluation.evaluations(), &scope).unwrap().into_inner();
                evaluation_claims_1_device.push(MleEval::new(eval_device));
            }

            let evaluation_claims_1_device =
                Evaluations { round_evaluations: evaluation_claims_1_device };

            let mut evaluation_claims_2_device = Vec::new();
            for evaluation in &evaluation_claims_2.round_evaluations {
                let eval_device =
                    DeviceTensor::from_host(evaluation.evaluations(), &scope).unwrap().into_inner();
                evaluation_claims_2_device.push(MleEval::new(eval_device));
            }
            let evaluation_claims_2 = Evaluations { round_evaluations: evaluation_claims_2_device };

            scope.synchronize_blocking().unwrap();

            let now = std::time::Instant::now();

            let new_basefold_proof = new_cuda_prover
                .prove_trusted_evaluations_basefold(
                    eval_point_host.clone(),
                    [evaluation_claims_1_device, evaluation_claims_2].into_iter().collect(),
                    &new_traces,
                    [&new_preprocessed_prover_data, &new_main_prover_data].into_iter().collect(),
                    &mut challenger,
                )
                .unwrap();

            scope.synchronize_blocking().unwrap();
            tracing::info!("New proof time: {:?}", now.elapsed());

            for (i, (a, b)) in basefold_proof
                .univariate_messages
                .iter()
                .zip_eq(new_basefold_proof.univariate_messages.iter())
                .enumerate()
            {
                assert_eq!(a, b, "Failure on message from round {}", i);
            }

            for (i, (a, b)) in basefold_proof
                .fri_commitments
                .iter()
                .zip_eq(new_basefold_proof.fri_commitments.iter())
                .enumerate()
            {
                assert_eq!(a, b, "Failure on FRI commitment from round {}", i);
            }

            assert_eq!(
                basefold_proof.final_poly, new_basefold_proof.final_poly,
                "Failure on final poly"
            );

            // Because the grinding is technically non-deterministic, the proof-of-work witnesses
            // do not need to be the same. Therefore, all the query indices are not necessarily the
            // same between the new and old proofs. However, the new proof should still verify.

            verifier
                .verify_mle_evaluations(
                    &[new_preprocessed_commit, new_main_commit],
                    eval_point_host,
                    &flattened_evaluation_claims,
                    &new_basefold_proof,
                    &mut SP1GlobalContext::default_challenger(),
                )
                .unwrap();
        })
        .unwrap();
    }
}
