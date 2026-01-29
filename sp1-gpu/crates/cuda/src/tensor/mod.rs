pub mod dot;
pub mod reduce;
mod sum;
pub mod transpose;

pub use dot::dot_along_dim_view;
use slop_alloc::{mem::CopyError, CpuBackend, HasBackend};
use slop_tensor::{Tensor, TensorView, TensorViewMut};
pub use transpose::DeviceTransposeKernel;

use crate::{DeviceBuffer, DeviceCopy};

use super::TaskScope;

#[derive(Debug, Clone)]
pub struct DeviceTensor<T> {
    raw: Tensor<T, TaskScope>,
}

impl<T: DeviceCopy> DeviceTensor<T> {
    /// Creates a DeviceTensor from a raw Tensor.
    pub fn from_raw(raw: Tensor<T, TaskScope>) -> Self {
        Self { raw }
    }

    /// Copies a device tensor reference to host memory (blocking).
    pub fn copy_to_host(tensor: &Tensor<T, TaskScope>) -> Result<Tensor<T, CpuBackend>, CopyError> {
        let host_storage = unsafe { tensor.storage.copy_into_host_buffer() };
        Ok(Tensor { storage: host_storage, dimensions: tensor.dimensions.clone() })
    }

    /// Marks the underlying tensor as initialized.
    ///
    /// # Safety
    /// See [`Tensor::assume_init`].
    pub unsafe fn assume_init(&mut self) {
        self.raw.assume_init();
    }

    pub fn with_sizes_in(sizes: impl AsRef<[usize]>, scope: TaskScope) -> Self {
        let raw = Tensor::with_sizes_in(sizes, scope);
        Self { raw }
    }

    /// Consumes self and returns the underlying Tensor.
    pub fn into_inner(self) -> Tensor<T, TaskScope> {
        self.raw
    }

    /// Copies the tensor to host memory (blocking).
    pub fn to_host(&self) -> Result<Tensor<T, CpuBackend>, CopyError> {
        let host_storage = unsafe { self.raw.storage.copy_into_host_buffer() };
        let tensor = Tensor { storage: host_storage, dimensions: self.raw.dimensions.clone() };
        Ok(tensor)
    }

    /// Creates a DeviceTensor from a host tensor (blocking).
    pub fn from_host(host_tensor: &Tensor<T>, scope: &TaskScope) -> Result<Self, CopyError> {
        let host_storage = &host_tensor.storage;
        let mut storage = DeviceBuffer::with_capacity_in(host_storage.len(), scope.clone());
        storage.extend(host_storage)?;
        let storage = storage.into_inner();

        let tensor = Tensor { storage, dimensions: host_tensor.dimensions.clone() };
        Ok(Self { raw: tensor })
    }

    pub fn sizes(&self) -> &[usize] {
        self.raw.sizes()
    }

    pub fn total_len(&self) -> usize {
        self.raw.total_len()
    }

    pub fn as_ptr(&self) -> *const T {
        self.raw.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.raw.as_mut_ptr()
    }

    pub fn backend(&self) -> &TaskScope {
        self.raw.backend()
    }

    pub fn view(&self) -> &Tensor<T, TaskScope> {
        &self.raw
    }

    pub fn as_view(&self) -> TensorView<'_, T, TaskScope> {
        self.raw.as_view()
    }

    pub fn as_mut_view(&mut self) -> TensorViewMut<'_, T, TaskScope> {
        self.raw.as_view_mut()
    }
}

impl<T: DeviceCopy> HasBackend for DeviceTensor<T> {
    type Backend = TaskScope;
    fn backend(&self) -> &TaskScope {
        self.raw.backend()
    }
}
