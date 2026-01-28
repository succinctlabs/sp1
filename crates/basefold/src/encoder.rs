use std::sync::Arc;

use slop_challenger::IopCtx;
use slop_dft::DftOrdering;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_merkle_tree::MerkleTree;
use sp1_gpu_utils::Felt;

use slop_algebra::{AbstractField, Field};
use slop_koala_bear::KoalaBear;
use slop_tensor::{Tensor, TensorView};
use sp1_gpu_cudart::{
    sys::dft::{batch_coset_dft, sppark_init_default_stream},
    CudaError, DeviceCopy,
};

pub fn encode_batch<'a>(
    dft: SpparkDftKoalaBear,
    log_blowup: u32,
    data: TensorView<'a, Felt, TaskScope>,
    dst: &mut Tensor<Felt, TaskScope>,
) -> Result<(), CudaError> {
    dft.coset_dft_into(
        data,
        dst,
        <Felt as AbstractField>::one(),
        log_blowup as usize,
        DftOrdering::BitReversed,
        1,
    )
    .unwrap();
    Ok(())
}

pub trait SpparkCudaDftSys<T: DeviceCopy>: 'static + Send + Sync {
    /// # Safety
    ///
    /// The caller must ensure the validity of pointers, allocation size, and lifetimes.
    #[allow(clippy::too_many_arguments)]
    unsafe fn dft_unchecked(
        &self,
        d_out: *mut T,
        d_in: *mut T,
        lg_domain_size: u32,
        lg_blowup: u32,
        shift: T,
        batch_size: u32,
        bit_rev_output: bool,
        backend: &TaskScope,
    ) -> Result<(), CudaError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpparkDft<F, T>(pub F, std::marker::PhantomData<T>);

#[derive(Clone)]
pub struct CudaStackedPcsProverData<GC: IopCtx> {
    /// The usizes are the height of the Merkle tree and the number of elements in a leaf.
    pub merkle_tree_tcs_data: (MerkleTree<GC::Digest, TaskScope>, GC::Digest, usize, usize),
    /// The codeword (encoded polynomial). This is `None` when `drop_traces` is true.
    pub codeword_mle: Option<Arc<Tensor<GC::F, TaskScope>>>,
}

impl<T: Field, F: SpparkCudaDftSys<T>> SpparkDft<F, T> {
    /// Performs a discrete Fourier transform along the last dimension of the input tensor.
    fn coset_dft_into<'a>(
        &self,
        src: TensorView<'a, T, TaskScope>,
        dst: &mut Tensor<T, TaskScope>,
        shift: T,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<(), CudaError> {
        let backend = src.backend();
        let d_in = src.as_ptr() as *mut T;
        let d_out = dst.as_mut_ptr();
        let src_dimensions = src.sizes();
        let dst_dimensions = dst.sizes();

        let shift = shift / T::generator();

        assert_eq!(
            src_dimensions[0], dst_dimensions[0],
            "dimension mismatch along the first dimension"
        );
        assert_eq!(src.sizes().len(), 2);
        assert_eq!(dst.sizes().len(), 2);
        assert_eq!(dim, 1);

        let lg_domain_size = src_dimensions[1].ilog2();
        let lg_blowup = dst_dimensions[1].ilog2() - lg_domain_size;
        assert_eq!(log_blowup, lg_blowup as usize);
        let batch_size = src_dimensions[0] as u32;
        let bit_rev_output = ordering == DftOrdering::BitReversed;

        unsafe {
            // Set the correct length for the output tensor
            dst.assume_init();
            // Call the function.
            self.0.dft_unchecked(
                d_out,
                d_in,
                lg_domain_size,
                lg_blowup,
                shift,
                batch_size,
                bit_rev_output,
                backend,
            )
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SpparkB31Kernels;

pub type SpparkDftKoalaBear = SpparkDft<SpparkB31Kernels, Felt>;

impl Default for SpparkB31Kernels {
    fn default() -> Self {
        unsafe { sppark_init_default_stream() };
        Self
    }
}

impl SpparkCudaDftSys<KoalaBear> for SpparkB31Kernels {
    unsafe fn dft_unchecked(
        &self,
        d_out: *mut KoalaBear,
        d_in: *mut KoalaBear,
        lg_domain_size: u32,
        lg_blowup: u32,
        shift: KoalaBear,
        batch_size: u32,
        bit_rev_output: bool,
        scope: &TaskScope,
    ) -> Result<(), CudaError> {
        CudaError::result_from_ffi(batch_coset_dft(
            d_out,
            d_in,
            lg_domain_size,
            lg_blowup,
            shift,
            batch_size,
            bit_rev_output,
            scope.handle(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::thread_rng;
    use slop_algebra::AbstractField;
    use slop_dft::{p3::Radix2DitParallel, Dft};

    use sp1_gpu_cudart::{run_sync_in_place, DeviceTensor};

    use super::*;

    #[test]
    fn test_batch_coset_dft() {
        let mut rng = thread_rng();

        let log_degrees = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let log_blowup = 1;
        let shift = KoalaBear::generator();
        let batch_size = 16;

        let p3_dft = Radix2DitParallel;

        for log_d in log_degrees.iter() {
            let d = 1 << log_d;

            let tensor_h = Tensor::<KoalaBear>::rand(&mut rng, [d, batch_size]);

            let tensor_h_sent = tensor_h.clone();
            let result = run_sync_in_place(|t| {
                let tensor_raw = DeviceTensor::from_host(&tensor_h_sent, &t).unwrap().into_inner();
                let tensor = DeviceTensor::from_raw(tensor_raw).transpose().into_inner();
                let dft = SpparkDftKoalaBear::default();
                let mut dst =
                    Tensor::<Felt, _>::with_sizes_in([batch_size, d << log_blowup], t.clone());
                dft.coset_dft_into(
                    tensor.as_view(),
                    &mut dst,
                    shift,
                    log_blowup,
                    DftOrdering::BitReversed,
                    1,
                )
                .unwrap();

                let result = DeviceTensor::from_raw(dst).transpose();
                result.to_host().unwrap()
            })
            .unwrap();

            let expected_result = p3_dft
                .coset_dft(&tensor_h, shift, log_blowup, DftOrdering::BitReversed, 0)
                .unwrap();

            for (i, (r, e)) in
                result.as_slice().iter().zip_eq(expected_result.as_slice()).enumerate()
            {
                assert_eq!(r, e, "Mismatch at index {i}");
            }
        }
    }
}
