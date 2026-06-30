use std::convert::Infallible;

pub use p3_dft::*;
use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_matrix::{bitrev::BitReversableMatrix, dense::RowMajorMatrix, Matrix};
use slop_tensor::Tensor;

use crate::{Dft, DftOrdering};

/// Coset DFT of `src` zero-extended (along the first dimension) to `padded_len` coefficient rows,
/// reusing `dst`'s allocation as the work buffer. Only `src`'s real data is ever copied; the zero
/// padding up to `padded_len` and the blowup tail are filled in place. `padded_len` must be a power
/// of two and at least `src`'s row count.
fn coset_dft_padded<F: TwoAdicField>(
    dft: &Radix2DitParallel,
    src: &Tensor<F, CpuBackend>,
    dest: &mut Tensor<F, CpuBackend>,
    padded_len: usize,
    shift: F,
    log_blowup: usize,
    ordering: DftOrdering,
) {
    assert_eq!(src.sizes().len(), 2);
    let src_rows = src.sizes()[0];
    let cols = src.sizes()[1];
    assert!(
        padded_len >= src_rows,
        "padded_len ({padded_len}) must be >= the source row count ({src_rows})"
    );
    assert!(padded_len.is_power_of_two(), "padded_len ({padded_len}) must be a power of two");

    // Note that the default value of a tensor is 0, so this doesn't allocate huge new things
    let dest_matrix = std::mem::take(dest);
    let mut dest_matrix: RowMajorMatrix<F> = dest_matrix.try_into().unwrap();

    // Clear the destination matrix (keeping its allocation as the DFT work buffer).
    dest_matrix.values.clear();
    // Copy the source rows in — this is the only copy of `src`'s data.
    dest_matrix.values.extend_from_slice(src.as_slice());
    // Zero-fill the rest: the coefficient rows from `src_rows` up to `padded_len` (the requested zero
    // padding) followed by the blowup tail. Both come for free from this resize, so a caller
    // encoding a non-power-of-two height never materializes its own padded copy.
    dest_matrix.values.resize((padded_len * cols) << log_blowup, F::zero());

    let result = dft.coset_dft_batch(dest_matrix, shift);

    let result_matrix = match ordering {
        DftOrdering::Normal => result.to_row_major_matrix(),
        DftOrdering::BitReversed => result.bit_reverse_rows().to_row_major_matrix(),
    };

    let mut result_tensor: Tensor<F, CpuBackend> = result_matrix.into();
    std::mem::swap(dest, &mut result_tensor);
}

impl<F: TwoAdicField> Dft<F, CpuBackend> for Radix2DitParallel {
    type Error = Infallible;

    fn coset_dft_into(
        &self,
        src: &Tensor<F, CpuBackend>,
        dst: &mut Tensor<F, CpuBackend>,
        shift: F,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<(), Self::Error> {
        assert_eq!(dst.sizes().len(), 2);
        assert_eq!(dim, 0, "Radix2DitParallel only supports DFT along the first dimension");
        // No extra padding: encode exactly `src`'s (power-of-two) row count.
        coset_dft_padded(self, src, dst, src.sizes()[0], shift, log_blowup, ordering);
        Ok(())
    }

    fn dft_zero_padded(
        &self,
        src: &Tensor<F, CpuBackend>,
        padded_len: usize,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<Tensor<F, CpuBackend>, Self::Error> {
        assert_eq!(dim, 0, "Radix2DitParallel only supports DFT along the first dimension");
        // Pre-size the output to the (padded, blown-up) row count so its allocation can serve as the
        // DFT work buffer.
        let mut sizes = src.sizes().to_vec();
        sizes[dim] = padded_len << log_blowup;
        let mut dst = Tensor::with_sizes_in(sizes, *src.backend());
        coset_dft_padded(self, src, &mut dst, padded_len, F::one(), log_blowup, ordering);
        Ok(dst)
    }
}
