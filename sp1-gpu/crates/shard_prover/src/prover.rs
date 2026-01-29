use crate::{MainTraceData, ShardData};
use slop_algebra::AbstractField;
use slop_alloc::{Buffer, HasBackend};
use slop_challenger::{CanObserve, FieldChallenger, FromChallenger, IopCtx};
use slop_commit::Rounds;
use slop_futures::queue::{Worker, WorkerQueue};
use slop_jagged::{
    unzip_and_prefix_sums, JaggedLittlePolynomialProverParams, JaggedPcsProof, JaggedProverData,
    JaggedProverError, PrefixSumsMaxLogRowCount,
};
use slop_multilinear::{Evaluations, MleEval, MultilinearPcsVerifier, Point};
use sp1_gpu_air::air_block::BlockAir;
use sp1_gpu_air::SymbolicProverFolder;
use sp1_gpu_basefold::{CudaStackedPcsProverData, DeviceGrindingChallenger, FriCudaProver};
use sp1_gpu_challenger::FromHostChallengerSync;
use sp1_gpu_cudart::PinnedBuffer;
use sp1_gpu_cudart::{DeviceMle, DevicePoint, TaskScope};
use sp1_gpu_jagged_assist::prove_jagged_evaluation_sync;
use sp1_gpu_jagged_sumcheck::{generate_jagged_sumcheck_poly, jagged_sumcheck};
use sp1_gpu_jagged_tracegen::{full_tracegen_permit, main_tracegen_permit, CudaShardProverData};
use sp1_gpu_logup_gkr::{prove_logup_gkr, CudaLogUpGkrOptions, Interactions};
use sp1_gpu_merkle_tree::{CudaTcsProver, SingleLayerMerkleTreeProverError};
use sp1_gpu_tracegen::CudaTracegenAir;
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle};
use sp1_gpu_zerocheck::zerocheck;
use sp1_gpu_zerocheck::CudaEvalResult;
use sp1_hypercube::prover::ZerocheckAir;
use sp1_hypercube::{
    air::{MachineAir, MachineProgram},
    prover::{AirProver, PreprocessedData, ProverPermit, ProverSemaphore, ProvingKey},
    Machine, MachineVerifyingKey, ShardProof,
};
use sp1_hypercube::{SP1PcsProof, ShardContextImpl};
use std::collections::BTreeMap;
use std::iter::once;
use std::{marker::PhantomData, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::Instrument;

pub trait CudaShardProverComponents<GC: IopCtx>: Send + Sync + 'static {
    type P: CudaTcsProver<GC>;
    type Air: CudaTracegenAir<GC::F>
        + ZerocheckAir<Felt, Ext>
        + for<'a> BlockAir<SymbolicProverFolder<'a>>;
    type C: MultilinearPcsVerifier<GC> + Send + Sync;
    /// The device challenger type used for GPU-based challenger operations.
    type DeviceChallenger: sp1_gpu_jagged_assist::AsMutRawChallenger
        + FromChallenger<GC::Challenger, TaskScope>
        + FromHostChallengerSync<GC::Challenger>
        + Clone
        + Send
        + Sync;
}

pub struct CudaShardProver<GC: IopCtx, PC: CudaShardProverComponents<GC>> {
    inner: Arc<CudaShardProverInner<GC, PC>>,
}

impl<GC: IopCtx, PC: CudaShardProverComponents<GC>> Clone for CudaShardProver<GC, PC> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<GC: IopCtx, PC: CudaShardProverComponents<GC>> CudaShardProver<GC, PC> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trace_buffers: Arc<WorkerQueue<PinnedBuffer<GC::F>>>,
        max_log_row_count: u32,
        basefold_prover: FriCudaProver<GC, PC::P, GC::F>,
        machine: Machine<GC::F, PC::Air>,
        max_trace_size: usize,
        backend: TaskScope,
        all_interactions: BTreeMap<String, Arc<Interactions<GC::F, TaskScope>>>,
        all_zerocheck_programs: BTreeMap<String, CudaEvalResult>,
        recompute_first_layer: bool,
        drop_ldes: bool,
    ) -> Self {
        Self {
            inner: Arc::new(CudaShardProverInner {
                trace_buffers,
                max_log_row_count,
                basefold_prover,
                machine,
                max_trace_size,
                backend,
                all_interactions,
                all_zerocheck_programs,
                recompute_first_layer,
                drop_ldes,
                _marker: PhantomData,
            }),
        }
    }
}

/// A prover for the hypercube STARK, given a configuration.
pub(crate) struct CudaShardProverInner<GC: IopCtx, PC: CudaShardProverComponents<GC>> {
    #[allow(clippy::type_complexity)]
    pub trace_buffers: Arc<WorkerQueue<PinnedBuffer<GC::F>>>,
    pub max_log_row_count: u32,
    pub basefold_prover: FriCudaProver<GC, PC::P, GC::F>,
    pub machine: Machine<GC::F, PC::Air>,
    pub max_trace_size: usize,
    pub backend: TaskScope,
    pub all_interactions: BTreeMap<String, Arc<Interactions<GC::F, TaskScope>>>,
    pub all_zerocheck_programs: BTreeMap<String, CudaEvalResult>,
    pub recompute_first_layer: bool,
    pub drop_ldes: bool,
    pub _marker: PhantomData<GC>,
}

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: CudaShardProverComponents<GC>>
    CudaShardProverInner<GC, PC>
{
    pub async fn get_buffer(&self) -> Worker<PinnedBuffer<GC::F>> {
        self.trace_buffers.clone().pop().await.expect("buffer pool exhausted")
    }

    fn machine(&self) -> &Machine<GC::F, PC::Air> {
        &self.machine
    }
}

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: CudaShardProverComponents<GC>>
    AirProver<GC, ShardContextImpl<GC, PC::C, PC::Air>> for CudaShardProver<GC, PC>
where
    GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
    GC::Challenger: slop_challenger::FieldChallenger<
        <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
    >,
    SP1PcsProof<GC>: Into<<PC::C as MultilinearPcsVerifier<GC>>::Proof>,
    TaskScope: sp1_gpu_jagged_assist::BranchingProgramKernel<GC::F, GC::EF, PC::DeviceChallenger>,
{
    type PreprocessedData = Mutex<CudaShardProverData<GC, PC::Air>>;

    fn machine(&self) -> &Machine<GC::F, PC::Air> {
        &self.inner.machine
    }

    /// Setup a shard, using a verifying key if provided.
    async fn setup_from_vk(
        &self,
        program: Arc<<PC::Air as MachineAir<GC::F>>::Program>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> (
        PreprocessedData<ProvingKey<GC, ShardContextImpl<GC, PC::C, PC::Air>, Self>>,
        MachineVerifyingKey<GC>,
    ) {
        let inner = self.inner.clone();
        if let Some(vk) = vk {
            let initial_global_cumulative_sum = vk.initial_global_cumulative_sum;
            inner
                .setup_with_initial_global_cumulative_sum(
                    program,
                    initial_global_cumulative_sum,
                    prover_permits,
                )
                .await
        } else {
            let program_sent = program.clone();
            let initial_global_cumulative_sum =
                tokio::task::spawn_blocking(move || program_sent.initial_global_cumulative_sum())
                    .await
                    .unwrap();
            inner
                .setup_with_initial_global_cumulative_sum(
                    program,
                    initial_global_cumulative_sum,
                    prover_permits,
                )
                .await
        }
    }

    /// Setup and prove a shard.
    async fn setup_and_prove_shard(
        &self,
        program: Arc<<PC::Air as MachineAir<GC::F>>::Program>,
        record: <PC::Air as MachineAir<GC::F>>::Record,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> (
        MachineVerifyingKey<GC>,
        ShardProof<GC, <PC::C as MultilinearPcsVerifier<GC>>::Proof>,
        ProverPermit,
    ) {
        // Get the initial global cumulative sum and pc start.
        let pc_start = program.pc_start();
        let enable_untrusted_programs = program.enable_untrusted_programs();
        let initial_global_cumulative_sum = if let Some(vk) = vk {
            vk.initial_global_cumulative_sum
        } else {
            let program = program.clone();
            tokio::task::spawn_blocking(move || program.initial_global_cumulative_sum())
                .instrument(tracing::debug_span!("initial_global_cumulative_sum"))
                .await
                .unwrap()
        };

        let buffer = self.inner.get_buffer().await;

        let record = Arc::new(record);

        // Generate trace.
        let (public_values, trace_data, chip_set, permit) = full_tracegen_permit(
            self.machine(),
            program,
            record,
            &buffer,
            self.inner.max_trace_size,
            self.inner.basefold_prover.log_height,
            self.inner.max_log_row_count,
            &self.inner.backend,
            prover_permits,
            true,
        )
        .instrument(tracing::debug_span!("generate all traces"))
        .await;

        let inner = self.inner.clone();
        let (pk, vk) = tokio::task::spawn_blocking({
            let span = tracing::debug_span!("setup_from_preprocessed_data_and_traces");
            move || {
                let _guard = span.enter();
                inner.setup_from_preprocessed_data_and_traces(
                    pc_start,
                    initial_global_cumulative_sum,
                    trace_data,
                    enable_untrusted_programs,
                )
            }
        })
        .await
        .unwrap();

        let trace_data = Mutex::new(pk);

        let pk = ProvingKey { vk: vk.clone(), preprocessed_data: trace_data };

        let pk = Arc::new(pk);

        let main_trace_data =
            MainTraceData { traces: pk, public_values, shard_chips: chip_set, permit };

        // Create a chanllenger
        let mut challenger = GC::default_challenger();
        // Observe the preprocessed information.
        vk.observe_into(&mut challenger);

        let shard_data = ShardData { main_trace_data };

        let inner = self.inner.clone();
        let (shard_proof, permit) = tokio::task::spawn_blocking({
            let span = tracing::debug_span!("prove_shard_with_data");
            move || {
                let _guard = span.enter();
                inner.prove_shard_with_data(shard_data, challenger)
            }
        })
        .await
        .unwrap();

        // tracing::debug_span!("prove shard with data")
        //     .in_scope(|| self.prove_shard_with_data(shard_data, challenger));
        drop(buffer);

        (vk, shard_proof, permit)
    }

    /// Prove a shard with a given proving key.
    async fn prove_shard_with_pk(
        &self,
        pk: Arc<ProvingKey<GC, ShardContextImpl<GC, PC::C, PC::Air>, Self>>,
        record: <PC::Air as MachineAir<GC::F>>::Record,
        prover_permits: ProverSemaphore,
    ) -> (ShardProof<GC, <PC::C as MultilinearPcsVerifier<GC>>::Proof>, ProverPermit) {
        // Generate the traces.
        let record = Arc::new(record);

        let buffer = self.inner.get_buffer().await;

        let (public_values, chip_set, permit) = main_tracegen_permit(
            &self.inner.machine,
            record,
            &pk.preprocessed_data,
            &buffer,
            self.inner.basefold_prover.log_height,
            self.inner.max_log_row_count,
            &self.inner.backend,
            prover_permits,
            true,
        )
        .instrument(tracing::debug_span!("generate main traces"))
        .await;

        let shard_data = ShardData {
            main_trace_data: MainTraceData {
                traces: pk.clone(),
                public_values,
                shard_chips: chip_set,
                permit,
            },
        };

        let mut challenger = GC::default_challenger();
        pk.vk.observe_into(&mut challenger);

        let inner = self.inner.clone();
        let (shard_proof, permit) = tokio::task::spawn_blocking({
            let span = tracing::debug_span!("prove_shard_with_data");
            move || {
                let _guard = span.enter();
                inner.prove_shard_with_data(shard_data, challenger)
            }
        })
        .await
        .unwrap();

        drop(buffer);

        (shard_proof, permit)
    }

    async fn preprocessed_table_heights(
        pk: Arc<ProvingKey<GC, ShardContextImpl<GC, PC::C, PC::Air>, Self>>,
    ) -> BTreeMap<String, usize> {
        // Access through pk.preprocessed_data which is of type CudaShardProverData
        let preprocessed_data = pk.preprocessed_data.lock().await;
        preprocessed_data
            .preprocessed_traces
            .dense()
            .preprocessed_table_index
            .iter()
            .map(|(name, offset)| (name.clone(), offset.poly_size))
            .collect()
    }
}

// An error type for cuda jagged prover
#[derive(Debug, Error)]
pub enum CudaShardProverError {}

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: CudaShardProverComponents<GC>>
    CudaShardProverInner<GC, PC>
{
    /// Commit to a batch of padded multilinears.
    ///
    /// The jagged polynomial commitments scheme is able to commit to sparse polynomials having
    /// very few or no real rows.
    /// **Note** the padding values will be ignored and treated as though they are zero.
    #[allow(clippy::type_complexity)]
    pub fn commit_multilinears(
        &self,
        multilinears: &JaggedTraceMle<Felt, TaskScope>,
        use_preprocessed_data: bool,
    ) -> Result<
        (GC::Digest, JaggedProverData<GC, CudaStackedPcsProverData<GC>>),
        JaggedProverError<SingleLayerMerkleTreeProverError>,
    > {
        sp1_gpu_commit::commit_multilinears::<GC, PC::P>(
            multilinears,
            self.max_log_row_count,
            use_preprocessed_data,
            self.drop_ldes,
            &self.basefold_prover,
        )
        .map_err(JaggedProverError::BatchPcsProverError)
    }

    pub fn round_stacked_evaluations(
        &self,
        stacked_point: &Point<Ext>,
        jagged_trace_mle: &JaggedTraceMle<Felt, TaskScope>,
    ) -> Rounds<Evaluations<Ext, TaskScope>> {
        let backend = jagged_trace_mle.backend();
        let log_stacking_height = stacked_point.len();
        let stacking_height = 1 << log_stacking_height;
        let preprocessed_stacked_size =
            jagged_trace_mle.dense().preprocessed_offset / stacking_height;
        let total_preprocessed_size = stacking_height * preprocessed_stacked_size;

        let device_point = DevicePoint::from_host(stacked_point, backend).unwrap();

        // todo: remove this assert, it's kinda useless
        assert!(total_preprocessed_size == jagged_trace_mle.dense().preprocessed_offset);
        let lagrange = device_point.partial_lagrange();

        let main_virtual_tensor =
            jagged_trace_mle.dense().main_virtual_tensor(log_stacking_height as u32);

        let preprocessed_virtual_tensor =
            jagged_trace_mle.dense().preprocessed_virtual_tensor(log_stacking_height as u32);

        let preprocessed_evaluations = MleEval::new(sp1_gpu_cudart::dot_along_dim_view(
            preprocessed_virtual_tensor,
            lagrange.guts().as_view(),
            1,
        ));

        let main_evaluations = MleEval::new(sp1_gpu_cudart::dot_along_dim_view(
            main_virtual_tensor,
            lagrange.guts().as_view(),
            1,
        ));

        let preprocessed_evaluations =
            Evaluations { round_evaluations: vec![preprocessed_evaluations] };

        let main_evaluations = Evaluations { round_evaluations: vec![main_evaluations] };

        Rounds::from_iter([preprocessed_evaluations, main_evaluations])
    }

    /// Prove trusted evaluations (sync version).
    #[allow(clippy::type_complexity)]
    pub fn prove_trusted_evaluations(
        &self,
        eval_point: Point<Ext>,
        evaluation_claims: Rounds<Evaluations<Ext, TaskScope>>,
        all_mles: &JaggedTraceMle<Felt, TaskScope>,
        prover_data: Rounds<&JaggedProverData<GC, CudaStackedPcsProverData<GC>>>,
        challenger: &mut GC::Challenger,
    ) -> Result<
        JaggedPcsProof<GC, <PC::C as MultilinearPcsVerifier<GC>>::Proof>,
        JaggedProverError<CudaShardProverError>,
    >
    where
        GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
        GC::Challenger: slop_challenger::FieldChallenger<
            <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
        >,
        SP1PcsProof<GC>: Into<<PC::C as MultilinearPcsVerifier<GC>>::Proof>,
        TaskScope:
            sp1_gpu_jagged_assist::BranchingProgramKernel<GC::F, GC::EF, PC::DeviceChallenger>,
    {
        let num_col_variables = prover_data
            .iter()
            .map(|data| data.column_counts.iter().sum::<usize>())
            .sum::<usize>()
            .next_power_of_two()
            .ilog2();
        let z_col = (0..num_col_variables)
            .map(|_| challenger.sample_ext_element::<Ext>())
            .collect::<Point<_>>();

        let z_row = eval_point.clone();

        let backend = evaluation_claims[0][0].backend().clone();

        // First, allocate a buffer for all of the column claims on device.
        let total_column_claims = evaluation_claims
            .iter()
            .map(|evals| evals.iter().map(|evals| evals.num_polynomials()).sum::<usize>())
            .sum::<usize>();

        // Add in the dummy padding columns added during the stacked PCS commitment.
        let total_len = total_column_claims
            + prover_data.iter().map(|data| data.padding_column_count).sum::<usize>();

        let mut column_claims: Buffer<Ext, TaskScope> =
            Buffer::with_capacity_in(total_len, backend.clone());

        // Then, copy the column claims from the evaluation claims into the buffer, inserting extra
        // zeros for the dummy columns.
        for (column_claim_round, data) in evaluation_claims.into_iter().zip(prover_data.iter()) {
            for column_claim in column_claim_round.into_iter() {
                column_claims
                    .extend_from_device_slice(column_claim.into_evaluations().as_buffer())?;
            }
            column_claims
                .extend_from_host_slice(vec![Ext::zero(); data.padding_column_count].as_slice())?;
        }

        assert!(prover_data
            .iter()
            .flat_map(|data| data.row_counts.iter())
            .all(|x| *x <= 1 << self.max_log_row_count));

        // Collect the jagged polynomial parameters.
        let params = JaggedLittlePolynomialProverParams::new(
            prover_data
                .iter()
                .flat_map(|data| {
                    data.row_counts
                        .iter()
                        .copied()
                        .zip(data.column_counts.iter().copied())
                        .flat_map(|(row_count, column_count)| {
                            std::iter::repeat_n(row_count, column_count)
                        })
                })
                .collect(),
            self.max_log_row_count as usize,
        );

        // Generate the jagged sumcheck proof.
        let z_row_device = DevicePoint::from_host(&z_row, &backend).unwrap();
        let z_col_device = DevicePoint::from_host(&z_col, &backend).unwrap();

        // The overall evaluation claim of the sparse polynomial is inferred from the individual
        // table claims.
        let device_column_claims = DeviceMle::from(column_claims);

        // Use the sync GPU evaluation
        let sumcheck_claims = device_column_claims.eval_at_point(&z_col_device);
        let sumcheck_claims_host = sumcheck_claims.to_host_vec().unwrap();
        let sumcheck_claim = sumcheck_claims_host[0];

        // Compute eq polynomials for the jagged sumcheck
        let eq_z_row = z_row_device.partial_lagrange();
        let eq_z_col = z_col_device.partial_lagrange();

        let sumcheck_poly = generate_jagged_sumcheck_poly(all_mles, eq_z_col, eq_z_row);

        let (sumcheck_proof, component_poly_evals) = tracing::debug_span!("jagged sumcheck")
            .in_scope(|| jagged_sumcheck(sumcheck_poly, challenger, sumcheck_claim));

        let final_eval_point = sumcheck_proof.point_and_eval.0.clone();

        // Use sync GPU jagged evaluation proof
        let jagged_eval_proof = tracing::debug_span!("jagged evaluation proof").in_scope(|| {
            prove_jagged_evaluation_sync::<Felt, Ext, GC::Challenger, PC::DeviceChallenger>(
                &params,
                &z_row,
                &z_col,
                &final_eval_point,
                challenger,
                &backend,
            )
        });

        let (row_counts, column_counts): (Rounds<_>, Rounds<_>) = prover_data
            .iter()
            .map(|data| {
                (Clone::clone(data.row_counts.as_ref()), Clone::clone(data.column_counts.as_ref()))
            })
            .unzip();

        let original_commitments: Rounds<_> =
            prover_data.iter().map(|data| data.original_commitment).collect();

        let stacked_prover_data =
            prover_data.iter().map(|data| &data.pcs_prover_data).collect::<Rounds<_>>();

        let final_eval_point = sumcheck_proof.point_and_eval.0.clone();

        let (_, stack_point) = final_eval_point
            .split_at(final_eval_point.dimension() - self.basefold_prover.log_height as usize);

        let batch_evaluations = self.round_stacked_evaluations(&stack_point, all_mles);

        challenger.observe_ext_element(component_poly_evals[0]);

        let mut host_batch_evaluations = Rounds::new();
        for round_evals in batch_evaluations.iter() {
            let mut host_round_evals = vec![];
            for eval in round_evals.iter() {
                let host_eval =
                    sp1_gpu_cudart::DeviceTensor::copy_to_host(eval.evaluations()).unwrap();
                host_round_evals.extend(host_eval.into_buffer().into_vec());
            }
            let host_round_evals = Evaluations::new(vec![host_round_evals.into()]);
            host_batch_evaluations.push(host_round_evals);
        }

        for round in batch_evaluations.iter() {
            for claim in round.iter() {
                let host_claim =
                    sp1_gpu_cudart::DeviceTensor::copy_to_host(claim.evaluations()).unwrap();
                for evaluation in host_claim.into_buffer().into_vec() {
                    challenger.observe_ext_element(evaluation);
                }
            }
        }

        let pcs_proof = tracing::debug_span!("prove trusted evaluations basefold")
            .in_scope(|| {
                self.basefold_prover.prove_trusted_evaluations_basefold(
                    stack_point,
                    batch_evaluations,
                    all_mles,
                    stacked_prover_data,
                    challenger,
                )
            })
            .unwrap();

        let row_counts_and_column_counts: Rounds<Vec<(usize, usize)>> = row_counts
            .into_iter()
            .zip(column_counts)
            .map(|(r, c)| r.into_iter().zip(c).collect())
            .collect();

        let host_batch_evaluations = host_batch_evaluations
            .into_iter()
            .map(|round| round.into_iter().flatten().collect::<MleEval<_>>())
            .collect::<Rounds<_>>();

        let stacked_basefold_proof =
            SP1PcsProof { basefold_proof: pcs_proof, batch_evaluations: host_batch_evaluations };

        let PrefixSumsMaxLogRowCount { log_m, .. } =
            unzip_and_prefix_sums(&row_counts_and_column_counts);

        Ok(JaggedPcsProof {
            pcs_proof: stacked_basefold_proof.into(),
            sumcheck_proof,
            jagged_eval_proof,
            row_counts_and_column_counts,
            merkle_tree_commitments: original_commitments,
            expected_eval: component_poly_evals[0],
            max_log_row_count: self.max_log_row_count as usize,
            log_m,
        })
    }

    fn commit_traces(
        &self,
        traces: &JaggedTraceMle<GC::F, TaskScope>,
        use_preprocessed: bool,
    ) -> (GC::Digest, JaggedProverData<GC, CudaStackedPcsProverData<GC>>) {
        self.commit_multilinears(traces, use_preprocessed).unwrap()
    }

    /// Prove a shard with the given data (sync version).
    /// This is the main proving function that runs on the GPU.
    #[allow(clippy::type_complexity)]
    pub fn prove_shard_with_data(
        &self,
        data: ShardData<GC, PC>,
        mut challenger: GC::Challenger,
    ) -> (ShardProof<GC, <PC::C as MultilinearPcsVerifier<GC>>::Proof>, ProverPermit)
    where
        GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
        GC::Challenger: slop_challenger::FieldChallenger<
            <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
        >,
        SP1PcsProof<GC>: Into<<PC::C as MultilinearPcsVerifier<GC>>::Proof>,
        TaskScope:
            sp1_gpu_jagged_assist::BranchingProgramKernel<GC::F, GC::EF, PC::DeviceChallenger>,
    {
        let ShardData { main_trace_data } = data;
        let MainTraceData { traces, public_values, shard_chips, permit } = main_trace_data;

        let shard_chips = self.machine().smallest_cluster(&shard_chips).unwrap();

        // Observe the public values.
        challenger.observe_slice(&public_values);

        let locked_preprocessed_data = traces.preprocessed_data.blocking_lock();
        let traces = &locked_preprocessed_data.preprocessed_traces;
        let preprocessed_data = &locked_preprocessed_data.preprocessed_data;

        // Commit to the traces.
        let (main_commit, main_data) =
            tracing::debug_span!("commit traces").in_scope(|| self.commit_traces(traces, false));
        // Observe the commitments.
        <GC::Challenger as CanObserve<GC::Digest>>::observe(&mut challenger, main_commit);
        challenger.observe(GC::F::from_canonical_usize(shard_chips.len()));

        for (chip_name, chip_height) in traces.dense().main_table_index.iter() {
            let chip_height = chip_height.poly_size;
            challenger.observe(GC::F::from_canonical_usize(chip_height));
            challenger.observe(GC::F::from_canonical_usize(chip_name.len()));
            for byte in chip_name.as_bytes() {
                challenger.observe(GC::F::from_canonical_u8(*byte));
            }
        }

        let max_interaction_arity = shard_chips
            .iter()
            .flat_map(|c| c.sends().iter().chain(c.receives().iter()))
            .map(|i| i.values.len() + 1)
            .max()
            .unwrap();
        let beta_seed_dim = max_interaction_arity.next_power_of_two().ilog2();

        // Sample the logup challenges.
        let alpha = challenger.sample_ext_element::<GC::EF>();

        let beta_seed = (0..beta_seed_dim)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();
        let _pv_challenge = challenger.sample_ext_element::<GC::EF>();

        let logup_gkr_proof = tracing::debug_span!("logup gkr proof").in_scope(|| {
            prove_logup_gkr::<GC, _, _>(
                shard_chips,
                self.all_interactions.clone(),
                traces,
                alpha,
                beta_seed,
                CudaLogUpGkrOptions {
                    recompute_first_layer: self.recompute_first_layer,
                    num_row_variables: self.max_log_row_count,
                },
                &mut challenger,
            )
        });
        // Get the challenge for batching constraints.
        let batching_challenge = challenger.sample_ext_element::<GC::EF>();
        // Get the challenge for batching the evaluations from the GKR proof.
        let gkr_opening_batch_challenge = challenger.sample_ext_element::<GC::EF>();

        // Generate the zerocheck proof.
        let (shard_open_values, zerocheck_partial_sumcheck_proof) =
            tracing::debug_span!("zerocheck").in_scope(|| {
                zerocheck(
                    shard_chips,
                    &self.all_zerocheck_programs,
                    traces,
                    batching_challenge,
                    gkr_opening_batch_challenge,
                    &logup_gkr_proof.logup_evaluations,
                    public_values.clone(),
                    &mut challenger,
                    self.max_log_row_count,
                )
            });

        // Get the evaluation point for the trace polynomials.
        let evaluation_point = zerocheck_partial_sumcheck_proof.point_and_eval.0.clone();
        let mut preprocessed_evaluation_claims: Option<Evaluations<GC::EF, TaskScope>> = None;
        let mut main_evaluation_claims = Evaluations::new(vec![]);

        let alloc = self.backend.clone();

        for (_, open_values) in shard_open_values.chips.iter() {
            let prep_local = &open_values.preprocessed.local;
            let main_local = &open_values.main.local;
            if !prep_local.is_empty() {
                let host_mle_eval = MleEval::from(prep_local.clone());
                let device_tensor =
                    sp1_gpu_cudart::DeviceTensor::from_host(host_mle_eval.evaluations(), &alloc)
                        .unwrap();
                let preprocessed_evals = MleEval::new(device_tensor.into_inner());
                if let Some(preprocessed_claims) = preprocessed_evaluation_claims.as_mut() {
                    preprocessed_claims.push(preprocessed_evals);
                } else {
                    let evals = Evaluations::new(vec![preprocessed_evals]);
                    preprocessed_evaluation_claims = Some(evals);
                }
            }
            let host_mle_eval = MleEval::from(main_local.clone());
            let device_tensor =
                sp1_gpu_cudart::DeviceTensor::from_host(host_mle_eval.evaluations(), &alloc)
                    .unwrap();
            let main_evals = MleEval::new(device_tensor.into_inner());
            main_evaluation_claims.push(main_evals);
        }

        let round_evaluation_claims = preprocessed_evaluation_claims
            .into_iter()
            .chain(once(main_evaluation_claims))
            .collect::<Rounds<_>>();

        let round_prover_data =
            once(preprocessed_data).chain(once(&main_data)).collect::<Rounds<_>>();

        // Generate the evaluation proof (sync call).
        let evaluation_proof = tracing::debug_span!("prove evaluation claims").in_scope(|| {
            self.prove_trusted_evaluations(
                evaluation_point,
                round_evaluation_claims,
                traces,
                round_prover_data,
                &mut challenger,
            )
            .unwrap()
        });

        let proof = ShardProof {
            main_commitment: main_commit,
            opened_values: shard_open_values,
            logup_gkr_proof,
            evaluation_proof,
            zerocheck_proof: zerocheck_partial_sumcheck_proof,
            public_values,
        };

        (proof, permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use slop_basefold::BasefoldVerifier;
    use slop_jagged::JaggedPcsVerifier;
    use slop_multilinear::MultilinearPcsChallenger;
    use slop_tensor::Tensor;
    use sp1_core_machine::riscv::RiscvAir;
    use sp1_gpu_air::codegen_cuda_eval;
    use sp1_gpu_cudart::run_in_place;
    use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
        self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
    };
    use sp1_gpu_jagged_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
    use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
    use sp1_gpu_utils::TestGC;
    use sp1_gpu_zerocheck::primitives::round_batch_evaluations;
    use sp1_hypercube::SP1InnerPcs;
    use sp1_primitives::fri_params::core_fri_config;

    pub struct TestProverComponentsImpl {}

    impl CudaShardProverComponents<TestGC> for TestProverComponentsImpl {
        type P = Poseidon2SP1Field16CudaProver;
        type Air = RiscvAir<Felt>;
        type C = SP1InnerPcs;
        type DeviceChallenger = sp1_gpu_challenger::DuplexChallenger<Felt, TaskScope>;
    }

    #[tokio::test]
    #[serial]
    async fn test_prove_trusted_evaluations() {
        let (machine, record, program) = tracegen_setup::setup().await;
        run_in_place(|scope| async move {
            // *********** Generate traces using the host tracegen. ***********
            let capacity = CORE_MAX_TRACE_SIZE as usize;
            let buffer = PinnedBuffer::<Felt>::with_capacity(capacity);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = queue.pop().await.unwrap();
            let (_public_values, jagged_trace_data, _shard_chips, _permit) = full_tracegen(
                &machine,
                program.clone(),
                Arc::new(record),
                &buffer,
                CORE_MAX_TRACE_SIZE as usize,
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT,
                &scope,
                ProverSemaphore::new(1),
                true,
            )
            .await;

            let jagged_trace_data = Arc::new(jagged_trace_data);

            let verifier = BasefoldVerifier::<TestGC>::new(core_fri_config(), 2);

            let basefold_prover = FriCudaProver::<TestGC, _, Felt>::new(
                Poseidon2SP1Field16CudaProver::new(&scope),
                verifier.fri_config,
                LOG_STACKING_HEIGHT,
            );

            let mut all_interactions = BTreeMap::new();

            for chip in machine.chips().iter() {
                let host_interactions = Interactions::new(chip.sends(), chip.receives());
                let device_interactions = host_interactions.copy_to_device(&scope).unwrap();
                all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
            }

            let mut cache = BTreeMap::new();
            for chip in machine.chips().iter() {
                let result = codegen_cuda_eval(chip.air.as_ref());
                cache.insert(chip.name().to_string(), result);
            }

            let num_workers = 1;
            let mut trace_buffers = Vec::with_capacity(num_workers);
            for _ in 0..num_workers {
                let buffer = PinnedBuffer::<Felt>::with_capacity(CORE_MAX_TRACE_SIZE as usize);
                trace_buffers.push(buffer);
            }

            let shard_prover_inner: CudaShardProverInner<TestGC, TestProverComponentsImpl> =
                CudaShardProverInner {
                    trace_buffers: Arc::new(WorkerQueue::new(trace_buffers)),
                    all_interactions,
                    all_zerocheck_programs: cache,
                    max_log_row_count: CORE_MAX_LOG_ROW_COUNT,
                    basefold_prover,
                    max_trace_size: CORE_MAX_TRACE_SIZE as usize,
                    machine,
                    recompute_first_layer: false,
                    drop_ldes: false,
                    backend: scope.clone(),
                    _marker: PhantomData,
                };
            let shard_prover = CudaShardProver { inner: Arc::new(shard_prover_inner) };

            let mut challenger = TestGC::default_challenger();

            let eval_point = challenger.sample_point(CORE_MAX_LOG_ROW_COUNT);

            // round_batch_evaluations is now sync and returns host evaluations
            let evaluation_claims =
                round_batch_evaluations(&eval_point, jagged_trace_data.as_ref());

            let (preprocessed_digest, preprocessed_prover_data) =
                shard_prover.inner.commit_multilinears(jagged_trace_data.as_ref(), true).unwrap();

            let (main_digest, main_prover_data) =
                shard_prover.inner.commit_multilinears(jagged_trace_data.as_ref(), false).unwrap();

            let prover_data = Rounds::from_iter([&preprocessed_prover_data, &main_prover_data]);

            // The evaluation_claims are already on host (CpuBackend).
            // We need to convert them to device evaluations for the prover.
            let mut new_evaluation_claims = Vec::new();
            for round_evals in evaluation_claims.iter() {
                let mut round_claims = Vec::new();
                for eval in round_evals.iter() {
                    // Copy the host MleEval to device
                    let device_tensor =
                        sp1_gpu_cudart::DeviceTensor::from_host(eval.evaluations(), &scope)
                            .unwrap();
                    let device_eval = MleEval::new(device_tensor.into_inner());
                    round_claims.push(device_eval);
                }
                let evals = Evaluations::new(round_claims);
                new_evaluation_claims.push(evals);
            }

            let mut prover_challenger = challenger.clone();
            let proof = shard_prover
                .inner
                .prove_trusted_evaluations(
                    eval_point.clone(),
                    new_evaluation_claims.into_iter().collect(),
                    jagged_trace_data.as_ref(),
                    prover_data,
                    &mut prover_challenger,
                )
                .unwrap();

            let jagged_verifier = JaggedPcsVerifier::<_, SP1InnerPcs>::new_from_basefold_params(
                core_fri_config(),
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT as usize,
                2,
            );

            // evaluation_claims are already on host, just extract the values
            let mut all_evaluations = Vec::new();
            for round_evals in evaluation_claims.iter() {
                let mut host_evals = Vec::new();
                for eval in round_evals.iter() {
                    // eval is already MleEval<Ext, CpuBackend>
                    host_evals.extend_from_slice(eval.evaluations().as_buffer().as_slice());
                }
                let buf = Buffer::from(host_evals);
                let mle_eval = MleEval::new(Tensor::from(buf));
                all_evaluations.push(mle_eval);
            }

            let mut verifier_challenger = challenger.clone();
            jagged_verifier
                .verify_trusted_evaluations(
                    &[preprocessed_digest, main_digest],
                    eval_point,
                    &all_evaluations,
                    &proof,
                    &mut verifier_challenger,
                )
                .unwrap();
        })
        .await;
    }
}
