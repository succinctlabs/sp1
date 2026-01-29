use sp1_gpu_sys::{
    runtime::{Dim3, KernelPtr},
    transpose::{
        transpose_kernel_koala_bear, transpose_kernel_koala_bear_digest,
        transpose_kernel_koala_bear_extension, transpose_kernel_u32, transpose_kernel_u32_digest,
    },
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
// TransposeBackend removed - using DeviceTensor methods instead

use crate::{args, DeviceCopy, DeviceTensor, TaskScope};

/// # Safety
pub unsafe trait DeviceTransposeKernel<T> {
    fn transpose_kernel() -> KernelPtr;
}

impl<T: DeviceCopy> DeviceTensor<T>
where
    TaskScope: DeviceTransposeKernel<T>,
{
    /// Transposes the tensor into the given destination tensor.
    pub fn transpose_into(&self, dst: &mut DeviceTensor<T>) {
        let src = &self.raw;
        let mut dst_view = dst.raw.as_view_mut();
        let num_dims = src.sizes().len();

        let dim_x = src.sizes()[num_dims - 2];
        let dim_y = src.sizes()[num_dims - 1];
        let dim_z: usize = src.sizes().iter().take(num_dims - 2).product();
        assert_eq!(dim_x, dst_view.sizes()[num_dims - 1]);
        assert_eq!(dim_y, dst_view.sizes()[num_dims - 2]);

        let block_dim: Dim3 = (32u32, 32u32, 1u32).into();
        let grid_dim: Dim3 = (
            dim_x.div_ceil(block_dim.x as usize),
            dim_y.div_ceil(block_dim.y as usize),
            dim_z.div_ceil(block_dim.z as usize),
        )
            .into();
        let args = args!(src.as_ptr(), dst_view.as_mut_ptr(), dim_x, dim_y, dim_z);
        unsafe {
            src.backend()
                .launch_kernel(TaskScope::transpose_kernel(), grid_dim, block_dim, &args, 0)
                .unwrap();
        }
    }

    /// Transposes the tensor and returns a new tensor.
    pub fn transpose(&self) -> DeviceTensor<T> {
        let src = &self.raw;
        let num_dims = src.sizes().len();
        let mut transposed_sizes = src.sizes().to_vec();
        transposed_sizes.swap(num_dims - 2, num_dims - 1);
        let mut dst = DeviceTensor::with_sizes_in(&transposed_sizes, src.backend().clone());
        unsafe {
            dst.assume_init();
        }
        self.transpose_into(&mut dst);
        dst
    }
}

unsafe impl DeviceTransposeKernel<u32> for TaskScope {
    fn transpose_kernel() -> KernelPtr {
        unsafe { transpose_kernel_u32() }
    }
}

unsafe impl DeviceTransposeKernel<[u32; 8]> for TaskScope {
    fn transpose_kernel() -> KernelPtr {
        unsafe { transpose_kernel_u32_digest() }
    }
}

unsafe impl DeviceTransposeKernel<SP1Field> for TaskScope {
    fn transpose_kernel() -> KernelPtr {
        unsafe { transpose_kernel_koala_bear() }
    }
}

unsafe impl DeviceTransposeKernel<SP1ExtensionField> for TaskScope {
    fn transpose_kernel() -> KernelPtr {
        unsafe { transpose_kernel_koala_bear_extension() }
    }
}

unsafe impl DeviceTransposeKernel<[SP1Field; 8]> for TaskScope {
    fn transpose_kernel() -> KernelPtr {
        unsafe { transpose_kernel_koala_bear_digest() }
    }
}

#[cfg(test)]
mod tests {
    use slop_tensor::Tensor;

    use super::*;

    #[test]
    fn test_tensor_transpose() {
        let mut rng = rand::thread_rng();

        for (height, width) in [
            (1024, 1024),
            (1024, 6),
            (6, 1024),
            (1024, 6),
            (1024, 2048),
            (2048, 1024),
            (2048, 2048),
            (1 << 22, 100),
        ] {
            let tensor = Tensor::<u32>::rand(&mut rng, [height, width]);
            let transposed_expected = tensor.transpose();
            let transposed = crate::run_sync_in_place(|t| {
                let device_tensor = DeviceTensor::from_host(&tensor, &t).unwrap();
                let transposed = device_tensor.transpose();
                transposed.to_host().unwrap()
            })
            .unwrap();

            for (val, expected) in
                transposed.as_buffer().iter().zip(transposed_expected.as_buffer().iter())
            {
                assert_eq!(*val, *expected);
            }
        }
    }
}
