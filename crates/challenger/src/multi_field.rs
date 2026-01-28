use slop_algebra::{Field, PrimeField32};
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend};
use slop_challenger::FromChallenger;
use slop_symmetric::CryptographicPermutation;
use sp1_gpu_cudart::{DeviceBuffer, TaskScope};

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MultiField32Challenger<F, PF, B: Backend> {
    pub sponge_state: Buffer<PF, B>,
    pub input_buffer: Buffer<F, B>,
    // [input_buffer_size, output_buffer_size, num_duplex_elms, num_f_elms]
    pub buffer_sizes: Buffer<usize, B>,
    pub output_buffer: Buffer<F, B>,
}

impl<
        F: PrimeField32,
        PF: Field,
        P: CryptographicPermutation<[PF; WIDTH]>,
        const WIDTH: usize,
        const RATE: usize,
    > From<slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>>
    for MultiField32Challenger<F, PF, CpuBackend>
{
    fn from(challenger: slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>) -> Self {
        let mut input_buffer = challenger.input_buffer;
        let input_buffer_size = input_buffer.len();
        assert!(input_buffer_size <= RATE * challenger.num_duplex_elms);
        input_buffer.resize(WIDTH * challenger.num_duplex_elms, F::zero());
        let mut output_buffer = challenger.output_buffer;
        let output_buffer_size = output_buffer.len();
        assert!(output_buffer_size <= WIDTH * challenger.num_f_elms);
        output_buffer.resize(WIDTH * challenger.num_f_elms, F::zero());
        let sponge_state = challenger.sponge_state;

        let input_buffer = Buffer::from(input_buffer);
        let output_buffer = Buffer::from(output_buffer);
        let sponge_state = Buffer::from(sponge_state.to_vec());
        let num_duplex_elms = challenger.num_duplex_elms;
        let num_f_elms = challenger.num_f_elms;
        let buffer_sizes =
            Buffer::from(vec![input_buffer_size, output_buffer_size, num_duplex_elms, num_f_elms]);

        Self { input_buffer, buffer_sizes, output_buffer, sponge_state }
    }
}

impl<F, PF, B: Backend> HasBackend for MultiField32Challenger<F, PF, B> {
    type Backend = B;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.sponge_state.backend()
    }
}

#[repr(C)]
pub struct MultiField32ChallengerRawMut<F, PF> {
    pub sponge_state: *mut PF,
    pub input_buffer: *mut F,
    pub buffer_sizes: *mut usize,
    pub output_buffer: *mut F,
}

impl<F, PF> MultiField32Challenger<F, PF, TaskScope> {
    pub fn as_mut_raw(&mut self) -> MultiField32ChallengerRawMut<F, PF> {
        MultiField32ChallengerRawMut {
            sponge_state: self.sponge_state.as_mut_ptr(),
            input_buffer: self.input_buffer.as_mut_ptr(),
            buffer_sizes: self.buffer_sizes.as_mut_ptr(),
            output_buffer: self.output_buffer.as_mut_ptr(),
        }
    }
}

impl<F: PrimeField32, PF: Field> MultiField32Challenger<F, PF, CpuBackend> {
    /// Copies this challenger to device memory synchronously.
    pub fn to_device_sync(
        self,
        backend: &TaskScope,
    ) -> Result<MultiField32Challenger<F, PF, TaskScope>, slop_alloc::mem::CopyError> {
        let input_buffer = DeviceBuffer::from_host(&self.input_buffer, backend)?.into_inner();
        let output_buffer = DeviceBuffer::from_host(&self.output_buffer, backend)?.into_inner();
        let sponge_state = DeviceBuffer::from_host(&self.sponge_state, backend)?.into_inner();
        let buffer_sizes = DeviceBuffer::from_host(&self.buffer_sizes, backend)?.into_inner();
        Ok(MultiField32Challenger { input_buffer, buffer_sizes, output_buffer, sponge_state })
    }
}

impl<F: Field, PF: Field> MultiField32Challenger<F, PF, TaskScope> {
    /// Copies this challenger to host memory synchronously.
    pub fn to_host_sync(
        self,
    ) -> Result<MultiField32Challenger<F, PF, CpuBackend>, slop_alloc::mem::CopyError> {
        let input_buffer = DeviceBuffer::from_raw(self.input_buffer).to_host()?.into();
        let output_buffer = DeviceBuffer::from_raw(self.output_buffer).to_host()?.into();
        let sponge_state = DeviceBuffer::from_raw(self.sponge_state).to_host()?.into();
        let buffer_sizes = DeviceBuffer::from_raw(self.buffer_sizes).to_host()?.into();
        Ok(MultiField32Challenger { input_buffer, buffer_sizes, output_buffer, sponge_state })
    }
}

impl<
        F: PrimeField32,
        PF: Field,
        P: CryptographicPermutation<[PF; WIDTH]> + Send + Sync,
        const WIDTH: usize,
        const RATE: usize,
    > FromChallenger<slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>, TaskScope>
    for MultiField32Challenger<F, PF, TaskScope>
{
    fn from_challenger(
        challenger: &slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>,
        backend: &TaskScope,
    ) -> Self {
        // Convert CPU challenger to our CPU representation, then copy to device synchronously
        let cpu_challenger: MultiField32Challenger<F, PF, CpuBackend> = challenger.clone().into();
        cpu_challenger.to_device_sync(backend).expect("failed to copy challenger to device")
    }
}

impl<
        F: PrimeField32,
        PF: Field,
        P: CryptographicPermutation<[PF; WIDTH]>,
        const WIDTH: usize,
        const RATE: usize,
    > crate::FromHostChallengerSync<slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>>
    for MultiField32Challenger<F, PF, TaskScope>
{
    fn from_host_challenger_sync(
        challenger: &slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>,
        backend: &TaskScope,
    ) -> Self {
        let cpu_challenger: MultiField32Challenger<F, PF, CpuBackend> = challenger.clone().into();
        cpu_challenger.to_device_sync(backend).expect("failed to copy challenger to device")
    }
}
