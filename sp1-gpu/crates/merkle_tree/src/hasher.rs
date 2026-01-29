use slop_algebra::Field;
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend};
use sp1_gpu_cudart::TaskScope;

pub struct MerkleTreeHasher<F: Field, A: Backend, const WIDTH: usize> {
    pub internal_constants: Buffer<F, A>,
    pub external_constants: Buffer<[F; WIDTH], A>,
    pub diffusion_matrix: Buffer<F, A>,
    pub monty_inverse: F,
}

/// The raw pointer equivalent of [`MerkleTreeHasher`] for use in cuda kernels.
#[repr(C)]
pub struct MerkleTreeHasherRaw<F: Field> {
    pub internal_constants: *const F,
    pub external_constants: *const F,
    pub diffusion_matrix: *const F,
    pub monty_inverse: F,
}

impl<F: Field, A: Backend, const WIDTH: usize> MerkleTreeHasher<F, A, WIDTH> {
    pub fn new(
        internal_constants: Buffer<F, A>,
        external_constants: Buffer<[F; WIDTH], A>,
        diffusion_matrix: Buffer<F, A>,
        monty_inverse: F,
    ) -> Self {
        Self { internal_constants, external_constants, diffusion_matrix, monty_inverse }
    }

    pub fn as_raw(&self) -> MerkleTreeHasherRaw<F> {
        MerkleTreeHasherRaw {
            internal_constants: self.internal_constants.as_ptr(),
            external_constants: self.external_constants.as_ptr() as *const F,
            diffusion_matrix: self.diffusion_matrix.as_ptr(),
            monty_inverse: self.monty_inverse,
        }
    }
}

/// implement default for merkletreehasher
impl<F: Field, const WIDTH: usize> Default for MerkleTreeHasher<F, CpuBackend, WIDTH> {
    fn default() -> Self {
        Self {
            internal_constants: Buffer::default(),
            external_constants: Buffer::default(),
            diffusion_matrix: Buffer::default(),
            monty_inverse: F::one(),
        }
    }
}

impl<F: Field, const WIDTH: usize, A: Backend> HasBackend for MerkleTreeHasher<F, A, WIDTH> {
    type Backend = A;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.internal_constants.backend()
    }
}

impl<F: Field, const WIDTH: usize> MerkleTreeHasher<F, CpuBackend, WIDTH> {
    /// Synchronously copy the hasher to the device.
    pub fn to_device_sync(
        &self,
        scope: &TaskScope,
    ) -> Result<MerkleTreeHasher<F, TaskScope, WIDTH>, slop_alloc::mem::CopyError> {
        let mut internal_constants =
            Buffer::with_capacity_in(self.internal_constants.len(), scope.clone());
        internal_constants.extend_from_host_slice(&self.internal_constants)?;

        let mut external_constants =
            Buffer::with_capacity_in(self.external_constants.len(), scope.clone());
        external_constants.extend_from_host_slice(&self.external_constants)?;

        let mut diffusion_matrix =
            Buffer::with_capacity_in(self.diffusion_matrix.len(), scope.clone());
        diffusion_matrix.extend_from_host_slice(&self.diffusion_matrix)?;

        Ok(MerkleTreeHasher {
            internal_constants,
            external_constants,
            diffusion_matrix,
            monty_inverse: self.monty_inverse,
        })
    }
}

// Async CopyToBackend impls removed - use sync to_device_sync method instead
