use sp1_primitives::SP1Field;

use crate::runtime::{CudaRustError, CudaStreamHandle, DEFAULT_STREAM};

/// # Safety
///
/// Initializes the selected GPU DFT backend.
pub unsafe fn dft_init_default_stream() -> CudaRustError {
    sppark_init(DEFAULT_STREAM)
}

/// # Safety
///
/// Initializes twiddle tables for the selected GPU DFT backend.
pub unsafe fn dft_init_twiddles(max_log_size: u32, stream: CudaStreamHandle) -> CudaRustError {
    dft_init_twiddles_sys(max_log_size, stream)
}

extern "C" {
    pub fn sppark_init(stream: CudaStreamHandle) -> CudaRustError;

    #[link_name = "dft_init_twiddles"]
    fn dft_init_twiddles_sys(max_log_size: u32, stream: CudaStreamHandle) -> CudaRustError;

    pub fn batch_coset_dft(
        d_out: *mut SP1Field,
        d_in: *mut SP1Field,
        lg_domain_size: u32,
        lg_blowup: u32,
        shift: SP1Field,
        poly_count: u32,
        is_bit_rev: bool,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn batch_lde_shift_in_place(
        d_inout: *mut SP1Field,
        lg_domain_size: u32,
        lg_blowup: u32,
        shift: SP1Field,
        poly_count: u32,
        is_bit_rev: bool,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn batch_coset_dft_in_place(
        d_inout: *mut SP1Field,
        lg_domain_size: u32,
        lg_blowup: u32,
        shift: SP1Field,
        poly_count: u32,
        is_bit_rev: bool,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn batch_NTT(
        d_inout: *mut SP1Field,
        lg_domain_size: u32,
        poly_count: u32,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn batch_iNTT(
        d_inout: *mut SP1Field,
        lg_domain_size: u32,
        poly_count: u32,
        stream: CudaStreamHandle,
    ) -> CudaRustError;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dft_init() {
        unsafe {
            assert!(dft_init_default_stream() == crate::runtime::CUDA_SUCCESS_CSL);
            assert!(dft_init_twiddles(15, DEFAULT_STREAM) == crate::runtime::CUDA_SUCCESS_CSL);
        }
    }
}
