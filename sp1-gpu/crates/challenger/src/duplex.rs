use slop_algebra::{Field, PrimeField64};
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend};
use slop_challenger::FromChallenger;
use slop_symmetric::CryptographicPermutation;
use sp1_gpu_cudart::{DeviceBuffer, TaskScope};

#[derive(Debug, Clone)]
#[repr(C)]
pub struct DuplexChallenger<F, B: Backend> {
    pub sponge_state: Buffer<F, B>,
    pub input_buffer: Buffer<F, B>,
    pub buffer_sizes: Buffer<usize, B>,
    pub output_buffer: Buffer<F, B>,
}

impl<
        F: PrimeField64,
        P: CryptographicPermutation<[F; WIDTH]>,
        const WIDTH: usize,
        const RATE: usize,
    > From<slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>>
    for DuplexChallenger<F, CpuBackend>
{
    fn from(challenger: slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>) -> Self {
        let mut input_buffer = challenger.input_buffer;
        let input_buffer_size = input_buffer.len();
        assert!(input_buffer_size <= WIDTH);
        input_buffer.resize(WIDTH, F::zero());
        let mut output_buffer = challenger.output_buffer;
        let output_buffer_size = output_buffer.len();
        assert!(output_buffer_size <= WIDTH);
        output_buffer.resize(WIDTH, F::zero());
        let sponge_state = challenger.sponge_state;
        assert!(sponge_state.len() == WIDTH);

        let input_buffer = Buffer::from(input_buffer);
        let output_buffer = Buffer::from(output_buffer);
        let sponge_state = Buffer::from(sponge_state.to_vec());

        Self {
            input_buffer,
            buffer_sizes: Buffer::from(vec![input_buffer_size, output_buffer_size]),
            output_buffer,
            sponge_state,
        }
    }
}

impl<F, B: Backend> HasBackend for DuplexChallenger<F, B> {
    type Backend = B;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.sponge_state.backend()
    }
}

#[repr(C)]
pub struct DuplexChallengerRawMut<F> {
    pub sponge_state: *mut F,
    pub input_buffer: *mut F,
    pub buffer_sizes: *mut usize,
    pub output_buffer: *mut F,
}

impl<F> DuplexChallenger<F, TaskScope> {
    pub fn as_mut_raw(&mut self) -> DuplexChallengerRawMut<F> {
        DuplexChallengerRawMut {
            sponge_state: self.sponge_state.as_mut_ptr(),
            input_buffer: self.input_buffer.as_mut_ptr(),
            buffer_sizes: self.buffer_sizes.as_mut_ptr(),
            output_buffer: self.output_buffer.as_mut_ptr(),
        }
    }
}

impl<F: Field> DuplexChallenger<F, CpuBackend> {
    /// Copies this challenger to device memory synchronously.
    pub fn to_device_sync(
        self,
        backend: &TaskScope,
    ) -> Result<DuplexChallenger<F, TaskScope>, slop_alloc::mem::CopyError> {
        let input_buffer = DeviceBuffer::from_host(&self.input_buffer, backend)?.into_inner();
        let output_buffer = DeviceBuffer::from_host(&self.output_buffer, backend)?.into_inner();
        let sponge_state = DeviceBuffer::from_host(&self.sponge_state, backend)?.into_inner();
        let buffer_sizes = DeviceBuffer::from_host(&self.buffer_sizes, backend)?.into_inner();
        Ok(DuplexChallenger { input_buffer, buffer_sizes, output_buffer, sponge_state })
    }
}

impl<F: Field> DuplexChallenger<F, TaskScope> {
    /// Copies this challenger to host memory synchronously.
    pub fn to_host_sync(
        self,
    ) -> Result<DuplexChallenger<F, CpuBackend>, slop_alloc::mem::CopyError> {
        let input_buffer = DeviceBuffer::from_raw(self.input_buffer).to_host()?.into();
        let output_buffer = DeviceBuffer::from_raw(self.output_buffer).to_host()?.into();
        let sponge_state = DeviceBuffer::from_raw(self.sponge_state).to_host()?.into();
        let buffer_sizes = DeviceBuffer::from_raw(self.buffer_sizes).to_host()?.into();
        Ok(DuplexChallenger { input_buffer, buffer_sizes, output_buffer, sponge_state })
    }
}

impl<
        F: PrimeField64,
        P: CryptographicPermutation<[F; WIDTH]> + Send + Sync,
        const WIDTH: usize,
        const RATE: usize,
    > FromChallenger<slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>, TaskScope>
    for DuplexChallenger<F, TaskScope>
{
    fn from_challenger(
        challenger: &slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>,
        backend: &TaskScope,
    ) -> Self {
        // Convert CPU challenger to our CPU representation, then copy to device synchronously
        let cpu_challenger: DuplexChallenger<F, CpuBackend> = challenger.clone().into();
        cpu_challenger.to_device_sync(backend).expect("failed to copy challenger to device")
    }
}

/// Trait for sync conversion from host challenger to device challenger.
/// This is used by the sync eval sumcheck functions to avoid async overhead.
pub trait FromHostChallengerSync<HostChallenger>: Sized {
    fn from_host_challenger_sync(challenger: &HostChallenger, backend: &TaskScope) -> Self;
}

impl<
        F: PrimeField64,
        P: CryptographicPermutation<[F; WIDTH]>,
        const WIDTH: usize,
        const RATE: usize,
    > FromHostChallengerSync<slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>>
    for DuplexChallenger<F, TaskScope>
{
    fn from_host_challenger_sync(
        challenger: &slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>,
        backend: &TaskScope,
    ) -> Self {
        let cpu_challenger: DuplexChallenger<F, CpuBackend> = challenger.clone().into();
        cpu_challenger.to_device_sync(backend).expect("failed to copy challenger to device")
    }
}
