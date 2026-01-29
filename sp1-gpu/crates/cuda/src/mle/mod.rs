mod base;
mod eval;
mod fold;
mod restrict;

use slop_algebra::Field;
use slop_alloc::Buffer;
use slop_alloc::{mem::CopyError, CpuBackend};
use slop_multilinear::{Mle, MleBaseBackend};

pub use eval::{DeviceMleEval, DevicePoint, PartialGeqKernel, PartialLagrangeKernel};
pub use fold::FoldKernel;
pub use restrict::MleFixLastVariableKernel;
use slop_tensor::Tensor;

use crate::tensor::transpose::DeviceTransposeKernel;
use crate::{DeviceCopy, DeviceTensor, TaskScope};

/// A multilinear extension (MLE) stored on the GPU device.
#[derive(Debug, Clone)]
pub struct DeviceMle<F> {
    guts: DeviceTensor<F>,
}

impl<F: DeviceCopy + Field> DeviceMle<F> {
    /// Creates a new DeviceMle from an Mle.
    pub fn new(guts: DeviceTensor<F>) -> Self {
        Self { guts }
    }

    fn from_tensor(tensor: Tensor<F, TaskScope>) -> Self {
        let tensor = DeviceTensor::from_raw(tensor);
        Self { guts: tensor }
    }

    pub fn uninit(
        num_polynomials: usize,
        num_non_zero_entries: usize,
        backend: &TaskScope,
    ) -> Self {
        let guts = backend.uninit_mle(num_polynomials, num_non_zero_entries);
        Self { guts: DeviceTensor::from_raw(guts) }
    }

    pub fn as_ptr(&self) -> *const F {
        self.guts.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut F {
        self.guts.as_mut_ptr()
    }

    /// Marks the underlying guts tensor as initialized.
    ///
    /// # Safety
    /// See [`Tensor::assume_init`].
    pub unsafe fn assume_init(&mut self) {
        self.guts.assume_init();
    }

    /// Returns a reference to the underlying guts tensor.
    pub fn guts(&self) -> &DeviceTensor<F> {
        &self.guts
    }

    pub fn guts_mut(&mut self) -> &mut DeviceTensor<F> {
        &mut self.guts
    }

    /// Consumes self and returns the underlying guts tensor as a DeviceTensor.
    pub fn into_guts(self) -> DeviceTensor<F> {
        self.guts
    }

    /// Returns the number of polynomials in this MLE.
    /// MLE guts shape is [num_polynomials, num_entries] for TaskScope convention
    pub fn num_polynomials(&self) -> usize {
        self.guts.sizes()[0]
    }

    /// Returns the number of variables in this MLE.
    pub fn num_variables(&self) -> u32 {
        self.guts.sizes()[1].next_power_of_two().ilog2()
    }

    /// Returns the number of non-zero entries in this MLE.
    pub fn num_non_zero_entries(&self) -> usize {
        self.guts.sizes()[1]
    }

    /// Returns the backend (TaskScope) for this MLE.
    pub fn backend(&self) -> &TaskScope {
        self.guts.backend()
    }

    fn into_mle(self) -> Mle<F, TaskScope> {
        Mle::new(self.guts.into_inner())
    }

    /// Copies a host MLE to the device.
    ///
    /// The host MLE uses CpuBackend convention [num_entries, num_polynomials].
    /// The device MLE uses TaskScope convention [num_polynomials, num_entries].
    /// This method transposes the data during copy to convert between conventions.
    pub fn from_host(host_mle: &Mle<F, CpuBackend>, scope: &TaskScope) -> Result<Self, CopyError>
    where
        TaskScope: DeviceTransposeKernel<F>,
    {
        let host_guts = host_mle.guts();
        // Host shape is [num_entries, num_polynomials]
        let device_guts_untransposed = DeviceTensor::from_host(host_guts, scope)?;
        // Transpose to [num_polynomials, num_entries] for TaskScope convention
        let device_guts = device_guts_untransposed.transpose();
        Ok(Self::new(device_guts))
    }

    /// Copies this MLE back to the host.
    ///
    /// The device MLE uses TaskScope convention [num_polynomials, num_entries].
    /// The host MLE uses CpuBackend convention [num_entries, num_polynomials].
    /// This method transposes the data during copy to convert between conventions.
    pub fn to_host(&self) -> Result<Mle<F, CpuBackend>, CopyError>
    where
        TaskScope: DeviceTransposeKernel<F>,
    {
        // Device shape is [num_polynomials, num_entries], transpose to [num_entries, num_polynomials]
        let transposed = self.guts.transpose();
        let host_guts = transposed.to_host()?;
        Ok(Mle::new(host_guts))
    }
}

impl<F: DeviceCopy + Field> From<Tensor<F, TaskScope>> for DeviceMle<F> {
    #[inline]
    fn from(tensor: Tensor<F, TaskScope>) -> Self {
        DeviceMle::from_tensor(tensor)
    }
}

impl<F: DeviceCopy + Field> From<Buffer<F, TaskScope>> for DeviceMle<F> {
    #[inline]
    fn from(buffer: Buffer<F, TaskScope>) -> Self {
        let len = buffer.len();
        let tensor = Tensor::from(buffer).reshape([1, len]);
        let mle = DeviceMle::from_tensor(tensor);
        assert_eq!(mle.num_polynomials(), 1);
        mle
    }
}

impl<F: DeviceCopy + Field> From<Mle<F, TaskScope>> for DeviceMle<F> {
    #[inline]
    fn from(tensor: Mle<F, TaskScope>) -> Self {
        DeviceMle::from_tensor(tensor.into_guts())
    }
}

impl<F: DeviceCopy + Field> From<DeviceMle<F>> for Mle<F, TaskScope> {
    #[inline]
    fn from(device_mle: DeviceMle<F>) -> Self {
        device_mle.into_mle()
    }
}
