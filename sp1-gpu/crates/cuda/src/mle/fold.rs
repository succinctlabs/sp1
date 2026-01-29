use slop_algebra::Field;
use slop_alloc::Backend;
use sp1_gpu_sys::{
    mle::{mle_fold_koala_bear_base_base, mle_fold_koala_bear_ext_ext},
    runtime::KernelPtr,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};

use crate::{args, DeviceCopy, DeviceTensor, TaskScope};

use super::DeviceMle;

/// # Safety
///
/// todo
pub unsafe trait FoldKernel<F: Field>: Backend {
    fn fold_kernel() -> KernelPtr;
}

impl<F: DeviceCopy + Field> DeviceMle<F>
where
    TaskScope: FoldKernel<F>,
{
    /// Folds the MLE by the given beta value.
    pub fn fold(&self, beta: F) -> DeviceMle<F> {
        let guts = self.guts();
        let num_polynomials = self.num_polynomials();
        let num_non_zero_entries = self.num_non_zero_entries();
        let folded_num_non_zero_entries = num_non_zero_entries / 2;
        // MLE guts shape is [num_polynomials, num_entries] for TaskScope convention
        let mut folded_guts = DeviceTensor::with_sizes_in(
            [num_polynomials, folded_num_non_zero_entries],
            self.backend().clone(),
        );

        const BLOCK_SIZE: usize = 256;
        const STRIDE: usize = 16;
        let block_dim = BLOCK_SIZE;
        let grid_size_x = folded_num_non_zero_entries.div_ceil(BLOCK_SIZE * STRIDE);
        let grid_size_y = num_polynomials;
        let grid_dim = (grid_size_x, grid_size_y, 1);
        let args = args!(
            guts.as_ptr(),
            folded_guts.as_mut_ptr(),
            beta,
            folded_num_non_zero_entries,
            num_polynomials
        );
        unsafe {
            folded_guts.assume_init();
            self.backend()
                .launch_kernel(TaskScope::fold_kernel(), grid_dim, block_dim, &args, 0)
                .unwrap();
        }
        DeviceMle::new(folded_guts)
    }
}

unsafe impl FoldKernel<SP1Field> for TaskScope {
    fn fold_kernel() -> KernelPtr {
        unsafe { mle_fold_koala_bear_base_base() }
    }
}

unsafe impl FoldKernel<SP1ExtensionField> for TaskScope {
    fn fold_kernel() -> KernelPtr {
        unsafe { mle_fold_koala_bear_ext_ext() }
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use slop_multilinear::Mle;
    use sp1_primitives::SP1ExtensionField;

    use crate::mle::DeviceMle;

    #[test]
    fn test_fold_mle() {
        let num_variables = 11;

        type EF = SP1ExtensionField;

        let mut rng = rand::thread_rng();

        let mle = Mle::<EF>::rand(&mut rng, 1, num_variables);
        let beta = rng.gen::<EF>();

        let folded_mle_host = mle.fold(beta);

        let folded_mle_cuda = crate::run_sync_in_place(|t| {
            let d_mle = DeviceMle::from_host(&mle, &t).unwrap();
            let folded_mle_cuda = d_mle.fold(beta);
            folded_mle_cuda.to_host().unwrap()
        })
        .unwrap();

        for (val, exp) in
            folded_mle_host.guts().as_slice().iter().zip(folded_mle_cuda.guts().as_slice())
        {
            assert_eq!(val, exp);
        }
    }
}
