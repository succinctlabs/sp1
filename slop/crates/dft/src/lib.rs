#![allow(clippy::disallowed_types)]
use std::error::Error;

use serde::{Deserialize, Serialize};
use slop_algebra::Field;
use slop_alloc::{Backend, CpuBackend};
use slop_tensor::Tensor;

pub mod p3;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DftOrdering {
    Normal,
    BitReversed,
}

pub trait Dft<T: Field, A: Backend = CpuBackend>: 'static + Send + Sync {
    type Error: Error;

    /// Perofrms a discrete Fourier transform along a given dimension.
    ///
    /// A `dft` implemelemtor may choose to:
    /// - Return an error if the dimension is not supported.
    /// - Return an error if the ordering is not supported.
    /// - Return an error if the shift is not supported.
    fn coset_dft_into(
        &self,
        src: &Tensor<T, A>,
        dst: &mut Tensor<T, A>,
        shift: T,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<(), Self::Error>;

    /// Discrete Fourier transform of `src` zero-extended along `dim` to `padded_len` coefficient
    /// rows (which must be a power of two and at least `src.sizes()[dim]`).
    ///
    /// The result is identical to first padding `src` with zero rows up to `padded_len` and calling
    /// [`Self::dft`], but an implementor may fold the zero padding into the buffer it has to load
    /// `src` into anyway — so the caller never has to materialize a padded copy of `src`. This lets a
    /// caller encode a non-power-of-two (or deliberately under-filled) input without an extra copy.
    /// The output has `padded_len << log_blowup` rows along `dim`.
    fn dft_zero_padded(
        &self,
        src: &Tensor<T, A>,
        padded_len: usize,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<Tensor<T, A>, Self::Error>;

    fn coset_dft(
        &self,
        src: &Tensor<T, A>,
        shift: T,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<Tensor<T, A>, Self::Error> {
        let mut sizes = src.sizes().to_vec();
        sizes[dim] <<= log_blowup;
        let mut dst = Tensor::with_sizes_in(sizes, src.backend().clone());
        self.coset_dft_into(src, &mut dst, shift, log_blowup, ordering, dim)?;
        Ok(dst)
    }

    fn dft_into(
        &self,
        src: &Tensor<T, A>,
        dst: &mut Tensor<T, A>,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<(), Self::Error> {
        self.coset_dft_into(src, dst, T::one(), log_blowup, ordering, dim)
    }

    fn dft(
        &self,
        src: &Tensor<T, A>,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<Tensor<T, A>, Self::Error> {
        self.coset_dft(src, T::one(), log_blowup, ordering, dim)
    }
}
