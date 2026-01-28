use slop_algebra::{extension::BinomialExtensionField, ExtensionField, Field};
use slop_alloc::{mem::CopyError, CpuBackend};
use slop_koala_bear::KoalaBear;
use slop_multilinear::{MleBaseBackend, MleEval, Point};
use slop_tensor::Tensor;
use sp1_gpu_sys::{
    mle::{
        partial_geq_koala_bear, partial_lagrange_koala_bear, partial_lagrange_koala_bear_extension,
    },
    runtime::KernelPtr,
};

use crate::{args, tensor::dot::DotKernel, DeviceCopy, DeviceTensor, TaskScope};

use super::DeviceMle;

/// A Point stored on the GPU device.
pub struct DevicePoint<F> {
    raw: Point<F, TaskScope>,
}

impl<F: DeviceCopy + Field> DevicePoint<F> {
    /// Creates a new DevicePoint from a Point.
    pub fn new(point: Point<F, TaskScope>) -> Self {
        Self { raw: point }
    }

    /// Returns a reference to the underlying Point.
    pub fn inner(&self) -> &Point<F, TaskScope> {
        &self.raw
    }

    /// Consumes self and returns the underlying Point.
    pub fn into_inner(self) -> Point<F, TaskScope> {
        self.raw
    }

    /// Returns the dimension of this point.
    pub fn dimension(&self) -> usize {
        self.raw.dimension()
    }

    /// Returns the backend (TaskScope) for this point.
    pub fn backend(&self) -> &TaskScope {
        self.raw.backend()
    }

    /// Returns a pointer to the underlying data.
    pub fn as_ptr(&self) -> *const F {
        self.raw.as_ptr()
    }

    /// Copies a host Point to the device.
    pub fn from_host(
        host_point: &Point<F, CpuBackend>,
        scope: &TaskScope,
    ) -> Result<Self, CopyError> {
        use slop_alloc::Buffer;
        let host_values = host_point.values();
        let mut device_buf = Buffer::with_capacity_in(host_values.len(), scope.clone());
        device_buf.extend_from_host_slice(host_values)?;
        Ok(Self::new(Point::new(device_buf)))
    }

    /// Computes the partial Lagrange polynomial for this point.
    pub fn partial_lagrange(&self) -> DeviceMle<F>
    where
        TaskScope: PartialLagrangeKernel<F>,
    {
        let dimension = self.dimension();
        let num_elements = 1 << dimension;
        // Shape [1, num_elements] to match MleBaseBackend convention for TaskScope: [num_polynomials, num_entries]
        let mut eq = DeviceTensor::with_sizes_in([1, num_elements], self.backend().clone());
        unsafe {
            eq.assume_init();
            let block_dim = 256;
            let grid_dim = ((1 << dimension) as u32).div_ceil(block_dim);
            let args = args!(eq.as_mut_ptr(), self.as_ptr(), dimension);
            self.backend()
                .launch_kernel(
                    <TaskScope as PartialLagrangeKernel<F>>::partial_lagrange_kernel(),
                    grid_dim,
                    block_dim,
                    &args,
                    0,
                )
                .unwrap();
        }
        DeviceMle::new(eq)
    }
}

/// MLE evaluations stored on the GPU device.
pub struct DeviceMleEval<F> {
    raw: MleEval<F, TaskScope>,
}

impl<F: DeviceCopy + Field> DeviceMleEval<F> {
    /// Creates a new DeviceMleEval from an MleEval.
    pub fn new(eval: MleEval<F, TaskScope>) -> Self {
        Self { raw: eval }
    }

    /// Returns a reference to the underlying MleEval.
    pub fn inner(&self) -> &MleEval<F, TaskScope> {
        &self.raw
    }

    /// Consumes self and returns the underlying MleEval.
    pub fn into_inner(self) -> MleEval<F, TaskScope> {
        self.raw
    }

    /// Returns a reference to the evaluations tensor.
    pub fn evaluations(&self) -> &Tensor<F, TaskScope> {
        self.raw.evaluations()
    }

    /// Copies the evaluations to the host and returns them as a Vec.
    pub fn to_host_vec(&self) -> Result<Vec<F>, CopyError> {
        let device_tensor = DeviceTensor::from_raw(self.raw.evaluations().clone());
        let host_tensor = device_tensor.to_host()?;
        Ok(host_tensor.into_buffer().into_vec())
    }
}

/// # Safety
///
pub unsafe trait PartialLagrangeKernel<F: Field> {
    fn partial_lagrange_kernel() -> KernelPtr;
}

/// # Safety
///
pub unsafe trait PartialGeqKernel<F: Field> {
    fn partial_geq_kernel() -> KernelPtr;
}

impl<F: DeviceCopy + Field> DeviceMle<F> {
    /// Evaluates the MLE at the given point.
    pub fn eval_at_point<EF: DeviceCopy + ExtensionField<F>>(
        &self,
        point: &DevicePoint<EF>,
    ) -> DeviceMleEval<EF>
    where
        TaskScope: PartialLagrangeKernel<EF> + DotKernel<F, EF>,
    {
        let eq = point.partial_lagrange();
        self.eval_at_eq(&eq)
    }

    /// Evaluates the MLE given precomputed eq polynomial.
    pub fn eval_at_eq<EF: DeviceCopy + ExtensionField<F>>(
        &self,
        eq: &DeviceMle<EF>,
    ) -> DeviceMleEval<EF>
    where
        TaskScope: DotKernel<F, EF>,
    {
        // MLE guts shape is [num_polynomials, num_entries] (TaskScope convention)
        // eq shape is [1, num_entries] from partial_lagrange
        // Dot along dim 1 reduces the num_entries dimension, giving [num_polynomials]
        let result = self.guts.dot_along_dim(eq.guts(), 1);
        DeviceMleEval::new(MleEval::new(result.into_inner()))
    }

    /// Evaluates the MLE at the given point with the last variable fixed to zero.
    /// This is equivalent to evaluating at (point, 0).
    pub fn fixed_at_zero<EF: DeviceCopy + ExtensionField<F>>(
        &self,
        point: &Point<EF>,
    ) -> DeviceMleEval<EF>
    where
        TaskScope: PartialLagrangeKernel<EF> + DotKernel<F, EF>,
    {
        // Extend the point with zero at the end
        let mut extended_point = point.clone();
        extended_point.add_dimension_back(EF::zero());
        let device_point = DevicePoint::from_host(&extended_point, self.backend()).unwrap();
        self.eval_at_point(&device_point)
    }
}

impl<F: Field> MleBaseBackend<F> for TaskScope {
    #[inline]
    fn uninit_mle(&self, num_polynomials: usize, num_non_zero_entries: usize) -> Tensor<F, Self> {
        // TaskScope convention: [num_polynomials, num_non_zero_entries]
        Tensor::with_sizes_in([num_polynomials, num_non_zero_entries], self.clone())
    }

    #[inline]
    fn num_polynomials(guts: &Tensor<F, Self>) -> usize {
        // TaskScope convention: sizes()[0] is num_polynomials
        guts.sizes()[0]
    }

    #[inline]
    fn num_variables(guts: &Tensor<F, Self>) -> u32 {
        // TaskScope convention: sizes()[1] is num_non_zero_entries
        guts.sizes()[1].next_power_of_two().ilog2()
    }

    #[inline]
    fn num_non_zero_entries(guts: &Tensor<F, Self>) -> usize {
        // TaskScope convention: sizes()[1] is num_non_zero_entries
        guts.sizes()[1]
    }
}

unsafe impl PartialLagrangeKernel<KoalaBear> for TaskScope {
    fn partial_lagrange_kernel() -> KernelPtr {
        unsafe { partial_lagrange_koala_bear() }
    }
}

unsafe impl PartialLagrangeKernel<BinomialExtensionField<KoalaBear, 4>> for TaskScope {
    fn partial_lagrange_kernel() -> KernelPtr {
        unsafe { partial_lagrange_koala_bear_extension() }
    }
}

unsafe impl PartialGeqKernel<KoalaBear> for TaskScope {
    fn partial_geq_kernel() -> KernelPtr {
        unsafe { partial_geq_koala_bear() }
    }
}

#[cfg(test)]
mod tests {
    use slop_algebra::extension::BinomialExtensionField;
    use slop_koala_bear::KoalaBear;
    use slop_multilinear::{Mle, Point};

    use super::{DeviceMleEval, DevicePoint};
    use crate::mle::DeviceMle;

    #[test]
    fn test_mle_eval() {
        let mut rng = rand::thread_rng();

        type F = KoalaBear;
        type EF = BinomialExtensionField<F, 4>;

        let mle = Mle::<F>::rand(&mut rng, 100, 16);
        let point = Point::<EF>::rand(&mut rng, 16);

        let evals = crate::run_sync_in_place(|t| {
            let d_point = DevicePoint::from_host(&point, &t).unwrap();
            let d_mle = DeviceMle::from_host(&mle, &t).unwrap();
            let eval: DeviceMleEval<EF> = d_mle.eval_at_point(&d_point);
            eval.to_host_vec().unwrap()
        })
        .unwrap();

        let host_evals = mle.eval_at(&point).to_vec();
        assert_eq!(evals, host_evals);
    }
}
