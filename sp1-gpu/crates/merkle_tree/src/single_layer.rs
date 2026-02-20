use std::{marker::PhantomData, os::raw::c_void};

use slop_algebra::{AbstractField, Field};
use slop_alloc::CpuBackend;
use slop_alloc::{mem::CopyError, Buffer, HasBackend};
use slop_bn254::{bn254_poseidon2_rc3, Bn254Fr, BNGC};
use slop_challenger::IopCtx;
use slop_merkle_tree::MerkleTreeTcsProof;
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use slop_tensor::Tensor;
use sp1_gpu_cudart::{
    args,
    sys::{
        merkle_tree::{
            compress_merkle_tree_bn254_kernel, compress_merkle_tree_koala_bear_16_kernel,
            compute_openings_merkle_tree_bn254_kernel,
            compute_openings_merkle_tree_koala_bear_16_kernel,
            compute_paths_merkle_tree_bn254_kernel, compute_paths_merkle_tree_koala_bear_16_kernel,
            leaf_hash_merkle_tree_bn254_kernel, leaf_hash_merkle_tree_koala_bear_16_kernel,
        },
        runtime::{Dim3, KernelPtr},
    },
    CudaError, DeviceTensor, TaskScope,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
use thiserror::Error;

use crate::{MerkleTree, MerkleTreeHasher};

/// # Safety
///
/// The implementor must make sure that the kernel signatures are the same as the ones expected
/// by [`MerkleTreeSingleLayerProver`].
pub unsafe trait MerkleTreeSingleLayerKernels<GC: IopCtx>: 'static + Send + Sync {
    fn leaf_hash_kernel() -> KernelPtr;

    fn compress_layer_kernel() -> KernelPtr;

    fn compute_paths_kernel() -> KernelPtr;

    fn compute_openings_kernel() -> KernelPtr;
}

pub trait Hasher<F: Field, const WIDTH: usize>: 'static + Send + Sync {
    fn hasher() -> MerkleTreeHasher<F, CpuBackend, WIDTH>;
}

pub struct MerkleTreeSingleLayerProver<GC, W: Field, K, H, const WIDTH: usize> {
    hasher_device: MerkleTreeHasher<W, TaskScope, WIDTH>,
    _marker: PhantomData<(GC, K, H)>,
}

#[derive(Debug, Clone, Copy, Error)]
pub enum SingleLayerMerkleTreeProverError {
    #[error("cuda error: {0}")]
    Cuda(#[from] CudaError),
    #[error("copy error: {0}")]
    Copy(#[from] CopyError),
}

type ProverError = SingleLayerMerkleTreeProverError;
pub type MerkleTreeProverData<Digest> = (MerkleTree<Digest, TaskScope>, Digest, usize, usize);

/// Because the single implementation of this trait is generic over many parameters that don't need
/// to be propagated up the stack, this trait defines the minimal API necessary to interact with the
/// Merkle tree prover and is generic only in the IopCtx.
pub trait CudaTcsProver<GC: IopCtx>: Send + Sync + 'static {
    fn new(scope: &TaskScope) -> Self
    where
        Self: Sized;

    fn commit_tensors(
        &self,
        tensor: &Tensor<GC::F, TaskScope>,
    ) -> Result<(GC::Digest, MerkleTreeProverData<GC::Digest>), ProverError>;

    fn prove_openings_at_indices(
        &self,
        data: &MerkleTreeProverData<GC::Digest>,
        indices: &[usize],
    ) -> Result<MerkleTreeTcsProof<GC::Digest>, ProverError>;

    fn compute_openings_at_indices(
        &self,
        tensors: &Tensor<GC::F, TaskScope>,
        indices: &[usize],
    ) -> Tensor<GC::F>;
}

impl<GC: IopCtx, W, K, H, const WIDTH: usize> CudaTcsProver<GC>
    for MerkleTreeSingleLayerProver<GC, W, K, H, WIDTH>
where
    W: Field,
    K: MerkleTreeSingleLayerKernels<GC>,
    H: Hasher<W, WIDTH>,
{
    fn new(scope: &TaskScope) -> Self {
        let hasher = H::hasher();
        let hasher_device = hasher.to_device_sync(scope).unwrap();
        Self { hasher_device, _marker: PhantomData }
    }

    fn commit_tensors(
        &self,
        tensor: &Tensor<GC::F, TaskScope>,
    ) -> Result<(GC::Digest, MerkleTreeProverData<GC::Digest>), ProverError> {
        let scope = tensor.backend();
        let hasher_device = &self.hasher_device;

        let height = tensor.sizes()[1].ilog2() as usize;
        let width = tensor.sizes()[0];

        assert_eq!(1 << height, tensor.sizes()[1], "Height must be a power of two");
        assert_eq!(tensor.sizes().len(), 2, "Tensor must be 2D");

        let mut tree = MerkleTree::<GC::Digest, _>::uninit(height, scope.clone());
        unsafe {
            tree.assume_init();
            // Compute the leaf hashes.
            let block_dim = 256;
            let grid_dim = (1usize << height).div_ceil(block_dim);
            let args = args!(
                hasher_device.as_raw(),
                tensor.as_ptr(),
                tree.digests.as_mut_ptr(),
                width,
                height
            );
            scope.launch_kernel(K::leaf_hash_kernel(), grid_dim, block_dim, &args, 0)?;
        }

        // Iterate over the layers and compute the compressions.
        for k in (0..height).rev() {
            let block_dim: Dim3 = (128u32, 4, 1).into();
            let grid_dim: Dim3 = ((1u32 << k).div_ceil(block_dim.x), 1, 1).into();
            let args = args!(hasher_device.as_raw(), tree.digests.as_mut_ptr(), k);
            unsafe {
                scope.launch_kernel(K::compress_layer_kernel(), grid_dim, block_dim, &args, 0)?;
            }
        }

        let (hasher, compressor) = GC::default_hasher_and_compressor();

        // Copy root digest from device to host synchronously
        let root = unsafe {
            let digests = tree.digests.owned_unchecked();
            digests[0].copy_into_host(scope)
        };

        let total_width = tensor.sizes()[0];
        let hash = hasher.hash_iter([
            GC::F::from_canonical_usize(height),
            GC::F::from_canonical_usize(total_width),
        ]);
        let compressed_root = compressor.compress([root, hash]);
        Ok((compressed_root, (tree, root, height, total_width)))
    }

    fn prove_openings_at_indices(
        &self,
        data: &MerkleTreeProverData<GC::Digest>,
        indices: &[usize],
    ) -> Result<MerkleTreeTcsProof<GC::Digest>, ProverError> {
        let paths = {
            let scope = data.0.backend();
            let mut paths = Tensor::<GC::Digest, _>::with_sizes_in(
                [indices.len(), data.0.height],
                scope.clone(),
            );
            let mut indices_buffer =
                Buffer::<usize, _>::with_capacity_in(indices.len(), scope.clone());
            indices_buffer.extend_from_host_slice(indices)?;
            let indices = indices_buffer;
            unsafe {
                paths.assume_init();

                let block_dim = 256;
                let grid_dim = indices.len().div_ceil(block_dim);
                let args = [
                    &(paths.as_mut_ptr()) as *const _ as *mut c_void,
                    &(indices.as_ptr()) as *const _ as *mut c_void,
                    &indices.len() as *const usize as _,
                    &(data.0.digests.as_ptr()) as *const _ as *mut c_void,
                    (&data.0.height) as *const usize as _,
                ];
                scope.launch_kernel(K::compute_paths_kernel(), grid_dim, block_dim, &args, 0)?;
            }
            paths
        };
        let paths = DeviceTensor::from_raw(paths).to_host().unwrap();

        Ok(MerkleTreeTcsProof {
            paths,
            log_tensor_height: data.2,
            width: data.3,
            merkle_root: data.1,
        })
    }

    fn compute_openings_at_indices(
        &self,
        tensors: &Tensor<GC::F, TaskScope>,
        indices: &[usize],
    ) -> Tensor<GC::F> {
        let openings = {
            let num_opening_values = tensors.sizes()[0];
            let (tensor_ptrs_host, widths_host): (Vec<_>, Vec<usize>) =
                (vec![tensors.as_ptr()], vec![num_opening_values]);
            let scope = tensors.backend();
            let num_inputs = 1usize;
            let mut tensor_ptrs = Buffer::with_capacity_in(tensor_ptrs_host.len(), scope.clone());
            tensor_ptrs.extend_from_host_slice(&tensor_ptrs_host).unwrap();
            let mut widths = Buffer::with_capacity_in(widths_host.len(), scope.clone());
            widths.extend_from_host_slice(&widths_host).unwrap();
            let tensor_height = tensors.sizes()[1];

            // Allocate tensors for the openings.
            let mut openings = Tensor::<GC::F, _>::with_sizes_in(
                [indices.len(), num_opening_values],
                scope.clone(),
            );
            let mut indices_buffer =
                Buffer::<usize, _>::with_capacity_in(indices.len(), scope.clone());
            indices_buffer.extend_from_host_slice(indices).unwrap();
            let indices = indices_buffer;

            let offsets = widths_host
                .iter()
                .scan(0, |offset, &width| {
                    let old_offset = *offset;
                    *offset += width;
                    Some(old_offset)
                })
                .collect::<Vec<_>>();

            let mut offsets_buffer =
                Buffer::<usize, _>::with_capacity_in(offsets.len(), scope.clone());
            offsets_buffer.extend_from_host_slice(&offsets).unwrap();
            let offsets = offsets_buffer;
            unsafe {
                openings.assume_init();

                let block_dim = 256;
                let grid_dim = indices.len().div_ceil(block_dim);
                let args = args!(
                    tensor_ptrs.as_ptr(),
                    openings.as_mut_ptr(),
                    indices.as_ptr(),
                    indices.len(),
                    num_inputs,
                    widths.as_ptr(),
                    offsets.as_ptr(),
                    tensor_height,
                    num_opening_values
                );
                scope
                    .launch_kernel(K::compute_openings_kernel(), grid_dim, block_dim, &args, 0)
                    .unwrap();
            }
            openings
        };
        DeviceTensor::from_raw(openings).to_host().unwrap()
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon2SP1Field16Kernels;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon2Bn254Kernels;

pub type Poseidon2SP1Field16CudaProver = MerkleTreeSingleLayerProver<
    SP1GlobalContext,
    SP1Field,
    Poseidon2SP1Field16Kernels,
    Poseidon2SP1Field16Hasher,
    16,
>;

pub type Poseidon2Bn254CudaProver = MerkleTreeSingleLayerProver<
    BNGC<SP1Field, SP1ExtensionField>,
    Bn254Fr,
    Poseidon2Bn254Kernels,
    Poseidon2Bn254Hasher,
    3,
>;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon2SP1Field16Hasher;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poseidon2Bn254Hasher;

impl Hasher<SP1Field, 16> for Poseidon2SP1Field16Hasher {
    fn hasher() -> MerkleTreeHasher<SP1Field, CpuBackend, 16> {
        MerkleTreeHasher::default()
    }
}

impl Hasher<Bn254Fr, 3> for Poseidon2Bn254Hasher {
    fn hasher() -> MerkleTreeHasher<Bn254Fr, CpuBackend, 3> {
        let (internal_round_constants, external_round_constants, diffusion_matrix_m1) =
            poseidon2_bn254_3_constants();
        MerkleTreeHasher::new(
            internal_round_constants.into(),
            external_round_constants.into(),
            diffusion_matrix_m1.into(),
            Bn254Fr::one(),
        )
    }
}

pub fn poseidon2_bn254_3_constants() -> (Vec<Bn254Fr>, Vec<[Bn254Fr; 3]>, Vec<Bn254Fr>) {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;
    let mut round_constants = bn254_poseidon2_rc3();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants =
        round_constants.drain(internal_start..internal_end).map(|vec| vec[0]).collect::<Vec<_>>();
    let external_round_constants = round_constants;
    let diffusion_matrix_m1 = [Bn254Fr::one(), Bn254Fr::one(), Bn254Fr::two()].to_vec();
    (internal_round_constants, external_round_constants, diffusion_matrix_m1)
}

unsafe impl MerkleTreeSingleLayerKernels<SP1GlobalContext> for Poseidon2SP1Field16Kernels {
    #[inline]
    fn leaf_hash_kernel() -> KernelPtr {
        unsafe { leaf_hash_merkle_tree_koala_bear_16_kernel() }
    }

    #[inline]
    fn compress_layer_kernel() -> KernelPtr {
        unsafe { compress_merkle_tree_koala_bear_16_kernel() }
    }

    #[inline]
    fn compute_paths_kernel() -> KernelPtr {
        unsafe { compute_paths_merkle_tree_koala_bear_16_kernel() }
    }

    #[inline]
    fn compute_openings_kernel() -> KernelPtr {
        unsafe { compute_openings_merkle_tree_koala_bear_16_kernel() }
    }
}

unsafe impl MerkleTreeSingleLayerKernels<BNGC<SP1Field, SP1ExtensionField>>
    for Poseidon2Bn254Kernels
{
    #[inline]
    fn leaf_hash_kernel() -> KernelPtr {
        unsafe { leaf_hash_merkle_tree_bn254_kernel() }
    }

    #[inline]
    fn compress_layer_kernel() -> KernelPtr {
        unsafe { compress_merkle_tree_bn254_kernel() }
    }

    #[inline]
    fn compute_paths_kernel() -> KernelPtr {
        unsafe { compute_paths_merkle_tree_bn254_kernel() }
    }

    #[inline]
    fn compute_openings_kernel() -> KernelPtr {
        unsafe { compute_openings_merkle_tree_bn254_kernel() }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slop_commit::Message;
    use slop_futures::queue::WorkerQueue;
    use slop_multilinear::Mle;
    use slop_stacked::interleave_multilinears_with_fixed_rate;
    use sp1_gpu_cudart::{run_in_place, PinnedBuffer};
    use sp1_hypercube::prover::{DefaultTraceGenerator, ProverSemaphore, TraceGenerator};

    use sp1_core_machine::io::SP1Stdin;
    use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
        self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
    };
    use sp1_gpu_jagged_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
    use sp1_gpu_utils::Felt;

    use super::*;
    use slop_merkle_tree::{ComputeTcsOpenings, TensorCsProver};

    #[tokio::test]
    async fn test_poseidon2_koala_bear_16() {
        let (machine, record, program) =
            tracegen_setup::setup(&test_artifacts::FIBONACCI_ELF, SP1Stdin::new()).await;

        run_in_place(|scope| async move {
            let old_prover = slop_merkle_tree::Poseidon2KoalaBear16Prover::default();

            // Generate traces using the host tracegen.
            let semaphore = ProverSemaphore::new(1);
            let trace_generator = DefaultTraceGenerator::new_in(machine.clone(), CpuBackend);
            let old_traces = trace_generator
                .generate_traces(
                    program.clone(),
                    record.clone(),
                    CORE_MAX_LOG_ROW_COUNT as usize,
                    semaphore.clone(),
                )
                .await;

            let preprocessed_traces = old_traces.preprocessed_traces.clone();

            let message = preprocessed_traces
                .into_iter()
                .filter_map(|mle| mle.1.into_inner())
                .map(|x| Clone::clone(x.as_ref()))
                .collect::<Message<Mle<_, _>>>();

            let interleaved_message =
                interleave_multilinears_with_fixed_rate(32, message, LOG_STACKING_HEIGHT);

            let interleaved_message = interleaved_message
                .into_iter()
                .map(|x| x.as_ref().guts().clone())
                .collect::<Message<_>>();

            let (old_preprocessed_commitment, old_prover_data) =
                old_prover.commit_tensors(interleaved_message.clone()).unwrap();

            let new_semaphore = ProverSemaphore::new(1);
            let capacity = CORE_MAX_TRACE_SIZE as usize;
            let buffer = PinnedBuffer::<Felt>::with_capacity(capacity);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = queue.pop().await.unwrap();

            let (_, new_traces, _, _) = full_tracegen(
                &machine,
                program,
                Arc::new(record),
                &buffer,
                CORE_MAX_TRACE_SIZE as usize,
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT,
                &scope,
                new_semaphore.clone(),
                false,
            )
            .await;
            let new_traces = Arc::new(new_traces);

            let tensor_prover = Poseidon2SP1Field16CudaProver::new(&scope);

            let (new_preprocessed_commit, new_cuda_prover_data) = tensor_prover
                .commit_tensors(&new_traces.dense().preprocessed_tensor(LOG_STACKING_HEIGHT))
                .unwrap();

            assert_eq!(new_preprocessed_commit, old_preprocessed_commitment);

            let indices = vec![42, 7];

            let old_proof =
                old_prover.prove_openings_at_indices(old_prover_data.clone(), &indices).unwrap();

            let old_openings =
                old_prover.compute_openings_at_indices(interleaved_message, &indices);

            let new_openings = tensor_prover.compute_openings_at_indices(
                &new_traces.dense().preprocessed_tensor(LOG_STACKING_HEIGHT),
                &indices,
            );

            let new_proof =
                tensor_prover.prove_openings_at_indices(&new_cuda_prover_data, &indices).unwrap();

            assert_eq!(new_proof.merkle_root, old_proof.merkle_root);
            assert_eq!(new_proof.log_tensor_height, old_proof.log_tensor_height);
            assert_eq!(new_proof.width, old_proof.width);
            assert_eq!(new_proof.paths, old_proof.paths);
            assert_eq!(new_openings, old_openings);

            let (new_main_commit, new_cuda_prover_data) = tensor_prover
                .commit_tensors(&new_traces.dense().main_tensor(LOG_STACKING_HEIGHT))
                .unwrap();
            let message = old_traces
                .main_trace_data
                .traces
                .into_iter()
                .filter_map(|mle| mle.1.into_inner())
                .map(|x| Clone::clone(x.as_ref()))
                .collect::<Message<Mle<_, _>>>();

            let interleaved_message =
                interleave_multilinears_with_fixed_rate(32, message, LOG_STACKING_HEIGHT);

            let interleaved_message = interleaved_message
                .into_iter()
                .map(|x| x.as_ref().guts().clone())
                .collect::<Message<_>>();

            let (old_main_commitment, old_prover_data) =
                old_prover.commit_tensors(interleaved_message.clone()).unwrap();

            assert_eq!(new_main_commit, old_main_commitment);

            let old_proof =
                old_prover.prove_openings_at_indices(old_prover_data.clone(), &indices).unwrap();

            let old_openings =
                old_prover.compute_openings_at_indices(interleaved_message, &indices);

            let new_openings = tensor_prover.compute_openings_at_indices(
                &new_traces.dense().main_tensor(LOG_STACKING_HEIGHT),
                &indices,
            );

            let new_proof =
                tensor_prover.prove_openings_at_indices(&new_cuda_prover_data, &indices).unwrap();

            assert_eq!(new_proof.merkle_root, old_proof.merkle_root);
            assert_eq!(new_proof.log_tensor_height, old_proof.log_tensor_height);
            assert_eq!(new_proof.width, old_proof.width);
            assert_eq!(new_proof.paths, old_proof.paths);
            assert_eq!(new_openings, old_openings);
        })
        .await
        .await
        .unwrap();
    }
}
