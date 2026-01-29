use std::sync::Arc;

use sp1_hypercube::SP1PcsProof;
use sp1_hypercube::ShardContextImpl;
use tokio::sync::Mutex;

use slop_challenger::IopCtx;
use slop_multilinear::MultilinearPcsVerifier;
use sp1_gpu_basefold::DeviceGrindingChallenger;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_jagged_tracegen::setup_tracegen_permit;
use sp1_gpu_jagged_tracegen::CudaShardProverData;
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle};
use sp1_hypercube::{
    air::{MachineAir, MachineProgram},
    prover::{PreprocessedData, ProverSemaphore, ProvingKey},
    septic_digest::SepticDigest,
    MachineVerifyingKey,
};

use crate::{CudaShardProver, CudaShardProverComponents, CudaShardProverInner};

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: CudaShardProverComponents<GC>> CudaShardProverInner<GC, PC>
where
    GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
    GC::Challenger: slop_challenger::FieldChallenger<
        <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
    >,
    SP1PcsProof<GC>: Into<<PC::C as MultilinearPcsVerifier<GC>>::Proof>,
    TaskScope: sp1_gpu_jagged_assist::BranchingProgramKernel<GC::F, GC::EF, PC::DeviceChallenger>,
{
    /// Setup from a program with a specific initial global cumulative sum.
    pub async fn setup_with_initial_global_cumulative_sum(
        self: Arc<Self>,
        program: Arc<<PC::Air as MachineAir<GC::F>>::Program>,
        initial_global_cumulative_sum: SepticDigest<GC::F>,
        setup_permits: ProverSemaphore,
    ) -> (
        PreprocessedData<
            ProvingKey<GC, ShardContextImpl<GC, PC::C, PC::Air>, CudaShardProver<GC, PC>>,
        >,
        MachineVerifyingKey<GC>,
    ) {
        let pc_start = program.pc_start();
        let enable_untrusted_programs = program.enable_untrusted_programs();

        let buffer = self.get_buffer().await;

        let (preprocessed_data, permit) = setup_tracegen_permit(
            &self.machine,
            program,
            &buffer,
            self.max_trace_size,
            self.basefold_prover.log_height,
            self.max_log_row_count,
            setup_permits,
            &self.backend,
        )
        .await;

        let inner = self.clone();
        let (pk, vk) = tokio::task::spawn_blocking(move || {
            inner.setup_from_preprocessed_data_and_traces(
                pc_start,
                initial_global_cumulative_sum,
                preprocessed_data,
                enable_untrusted_programs,
            )
        })
        .await
        .unwrap();

        let pk = Mutex::new(pk);

        let pk = ProvingKey { vk: vk.clone(), preprocessed_data: pk };

        let pk = Arc::new(pk);

        (PreprocessedData { pk, permit }, vk)
    }

    /// Setup from preprocessed data and traces.
    pub fn setup_from_preprocessed_data_and_traces(
        &self,
        pc_start: [GC::F; 3],
        initial_global_cumulative_sum: SepticDigest<GC::F>,
        preprocessed_traces: JaggedTraceMle<Felt, TaskScope>,
        enable_untrusted_programs: GC::F,
    ) -> (CudaShardProverData<GC, PC::Air>, MachineVerifyingKey<GC>) {
        // Commit to the preprocessed traces, if there are any.
        let (preprocessed_commit, preprocessed_data) = sp1_gpu_commit::commit_multilinears(
            &preprocessed_traces,
            self.max_log_row_count,
            true,
            self.drop_ldes,
            &self.basefold_prover,
        )
        .unwrap();

        let vk = MachineVerifyingKey {
            pc_start,
            initial_global_cumulative_sum,
            preprocessed_commit,
            enable_untrusted_programs,
        };

        let pk = CudaShardProverData::new(preprocessed_traces, preprocessed_data);

        (pk, vk)
    }
}
