use std::sync::Arc;

use slop_algebra::{extension::BinomialExtensionField, ExtensionField, Field};
use slop_koala_bear::KoalaBear;
use slop_multilinear::MleEval;
use sp1_gpu_sys::{
    runtime::KernelPtr,
    v2_kernels::{
        fix_last_variable_ext_ext_kernel, fix_last_variable_felt_ext_kernel,
        mle_fix_last_variable_koala_bear_base_extension_constant_padding,
        mle_fix_last_variable_koala_bear_ext_ext_constant_padding,
    },
};

use crate::{args, DeviceCopy, DeviceTensor, TaskScope};

use super::DeviceMle;

/// # Safety
pub unsafe trait MleFixLastVariableKernel<F: Field, EF: ExtensionField<F>> {
    fn mle_fix_last_variable_kernel() -> KernelPtr;

    fn mle_fix_last_variable_constant_padding_kernel() -> KernelPtr;
}

impl<F: DeviceCopy + Field> DeviceMle<F> {
    /// Fix the last variable of the MLE at the given alpha value.
    pub fn fix_last_variable<EF: DeviceCopy + ExtensionField<F>>(
        &self,
        alpha: EF,
        padding_values: Arc<MleEval<F, TaskScope>>,
    ) -> DeviceMle<EF>
    where
        TaskScope: MleFixLastVariableKernel<F, EF>,
    {
        let mle = self.guts();
        let num_polynomials = self.num_polynomials();
        // MLE guts shape is [num_polynomials, num_entries] for TaskScope convention
        let input_height = mle.sizes()[1];
        assert!(input_height > 0);
        let output_height = input_height.div_ceil(2);
        let mut output =
            DeviceTensor::with_sizes_in([num_polynomials, output_height], self.backend().clone());

        const BLOCK_SIZE: usize = 256;
        const STRIDE: usize = 128;
        let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE);
        let grid_size_y = num_polynomials;
        let grid_size = (grid_size_x, grid_size_y, 1);

        let args = args!(
            mle.as_ptr(),
            output.as_mut_ptr(),
            padding_values.evaluations().as_ptr(),
            alpha,
            input_height,
            num_polynomials
        );

        unsafe {
            output.assume_init();
            self.backend()
                .launch_kernel(
                    <TaskScope as MleFixLastVariableKernel<F, EF>>::mle_fix_last_variable_kernel(),
                    grid_size,
                    BLOCK_SIZE,
                    &args,
                    0,
                )
                .unwrap();
        }

        DeviceMle::new(output)
    }

    /// Fix the last variable of the MLE at the given alpha value with constant padding.
    pub fn fix_last_variable_constant_padding<EF: DeviceCopy + ExtensionField<F>>(
        &self,
        alpha: EF,
        padding_value: F,
    ) -> DeviceMle<EF>
    where
        TaskScope: MleFixLastVariableKernel<F, EF>,
    {
        let mle = self.guts();
        let num_polynomials = self.num_polynomials();
        // MLE guts shape is [num_polynomials, num_entries] for TaskScope convention
        let input_height = mle.sizes()[1];
        assert!(input_height > 0);
        let output_height = input_height.div_ceil(2);
        let mut output =
            DeviceTensor::with_sizes_in([num_polynomials, output_height], self.backend().clone());

        const BLOCK_SIZE: usize = 256;
        const STRIDE: usize = 128;
        let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE);
        let grid_size_y = num_polynomials;
        let grid_size = (grid_size_x, grid_size_y, 1);

        let args = args!(
            mle.as_ptr(),
            output.as_mut_ptr(),
            padding_value,
            alpha,
            input_height,
            num_polynomials
        );

        unsafe {
            output.assume_init();
            self.backend()
                .launch_kernel(
                    <TaskScope as MleFixLastVariableKernel<F, EF>>::mle_fix_last_variable_constant_padding_kernel(),
                    grid_size,
                    BLOCK_SIZE,
                    &args,
                    0,
                )
                .unwrap();
        }

        DeviceMle::new(output)
    }
}

unsafe impl MleFixLastVariableKernel<KoalaBear, BinomialExtensionField<KoalaBear, 4>>
    for TaskScope
{
    fn mle_fix_last_variable_kernel() -> KernelPtr {
        unsafe { fix_last_variable_felt_ext_kernel() }
    }
    fn mle_fix_last_variable_constant_padding_kernel() -> KernelPtr {
        unsafe { mle_fix_last_variable_koala_bear_base_extension_constant_padding() }
    }
}

unsafe impl
    MleFixLastVariableKernel<
        BinomialExtensionField<KoalaBear, 4>,
        BinomialExtensionField<KoalaBear, 4>,
    > for TaskScope
{
    fn mle_fix_last_variable_kernel() -> KernelPtr {
        unsafe { fix_last_variable_ext_ext_kernel() }
    }

    fn mle_fix_last_variable_constant_padding_kernel() -> KernelPtr {
        unsafe { mle_fix_last_variable_koala_bear_ext_ext_constant_padding() }
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_algebra::AbstractField;
    use slop_koala_bear::KoalaBear;
    use slop_multilinear::{Mle, Point};
    use slop_tensor::Tensor;

    use crate::mle::eval::DevicePoint;
    use crate::mle::DeviceMle;

    #[test]
    fn test_mle_fix_last_variable_constant_padding() {
        let mut rng = rand::thread_rng();

        type F = KoalaBear;
        type EF = BinomialExtensionField<F, 4>;

        let mle = Mle::<F>::new(Tensor::rand(&mut rng, [(1 << 16) - 1000, 1]));
        let random_point = Point::<EF>::rand(&mut rng, 15);
        let alpha = rng.gen::<EF>();

        let evals = crate::run_sync_in_place(|t| {
            let d_mle = DeviceMle::from_host(&mle, &t).unwrap();
            // Using fix_last_variable_constant_padding with F::zero() is equivalent
            // to the host's fix_last_variable method.
            let restriction = d_mle.fix_last_variable_constant_padding(alpha, F::zero());
            let d_point = DevicePoint::from_host(&random_point, &t).unwrap();
            let eval = restriction.eval_at_point(&d_point);
            eval.to_host_vec().unwrap()
        })
        .unwrap();

        // Host's fix_last_variable uses zero padding internally
        let restriction = mle.fix_last_variable(alpha);
        let host_evals = restriction.eval_at(&random_point).to_vec();

        assert_eq!(evals, host_evals);
    }

    // Note: The spawned tests and PaddedMle tests are commented out as they require
    // the async spawn interface which is not part of this sync refactor.
}
