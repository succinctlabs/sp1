use slop_tensor::{Tensor, TensorView};
use sp1_gpu_sys::{
    reduce::{
        dot_along_short_dimension_kernel_koala_bear_base_base,
        dot_along_short_dimension_kernel_koala_bear_base_extension,
        dot_along_short_dimension_kernel_koala_bear_extension_extension,
        partial_dot_koala_bear_base_extension_kernel, partial_dot_koala_bear_extension_kernel,
        partial_dot_koala_bear_kernel,
    },
    runtime::KernelPtr,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};

use crate::{args, reduce::partial_sum_reduction_into, DeviceCopy, DeviceTensor, TaskScope};

use super::reduce::DeviceSumKernel;

/// # Safety
///
pub unsafe trait DotKernel<T: DeviceCopy, U: DeviceCopy>: DeviceSumKernel<U> {
    fn partial_dot_kernel_last_dim() -> KernelPtr;

    fn dot_along_short_dimension_kernel() -> KernelPtr;
}

pub fn dot_along_dim_view<'a, T: DeviceCopy, U: DeviceCopy>(
    src: TensorView<'a, T, TaskScope>,
    scalars: TensorView<'a, U, TaskScope>,
    dim: usize,
) -> Tensor<U, TaskScope>
where
    TaskScope: DotKernel<T, U>,
{
    let mut sizes = src.sizes().to_vec();
    sizes.remove(dim);
    let mut dst = Tensor::with_sizes_in(sizes, src.backend().clone());
    assert_eq!(src.sizes().len(), 2, "Dot product only supported for 2D tensors",);
    let max_scalar_dim = *scalars.sizes().iter().max().unwrap();
    assert_eq!(max_scalar_dim, scalars.total_len(), "The scalar tensor must be a 1D tensor");
    match dim {
        dim if dim == src.sizes().len() - 1 => {
            let height = src.sizes()[dim];
            let width = src.total_len() / height;

            let null_ptr = std::ptr::null::<std::ffi::c_void>();
            let partial_args = args!(null_ptr, src.as_ptr(), scalars.as_ptr(), width, height);
            const BLOCK_SIZE: usize = 256;
            const INTIAL_STRIDE: usize = 4;
            dst.storage.write_bytes(0, dst.total_len() * std::mem::size_of::<U>()).unwrap();
            unsafe {
                partial_sum_reduction_into::<U, BLOCK_SIZE, INTIAL_STRIDE, 5>(
                    dst.as_view_mut(),
                    TaskScope::partial_dot_kernel_last_dim(),
                    partial_args,
                    0,
                    src.shape(),
                    dim,
                    src.backend(),
                );
            }
        }
        0 => {
            let height = src.sizes()[1];
            let width = src.total_len() / height;

            const BLOCK_SIZE: usize = 256;
            let args = args!(dst.as_mut_ptr(), src.as_ptr(), scalars.as_ptr(), width, height);
            let grid_dim = height.div_ceil(BLOCK_SIZE);
            unsafe {
                dst.assume_init();
                src.backend()
                    .launch_kernel(
                        TaskScope::dot_along_short_dimension_kernel(),
                        grid_dim,
                        BLOCK_SIZE,
                        &args,
                        0,
                    )
                    .unwrap();
            }
        }
        _ => panic!(
            "Dot product is not supported along dimension {} for tensor of sizes {:?}",
            dim,
            src.sizes()
        ),
    }
    dst
}

impl<T: DeviceCopy> DeviceTensor<T> {
    pub fn dot_along_dim<U: DeviceCopy>(
        &self,
        scalars: &DeviceTensor<U>,
        dim: usize,
    ) -> DeviceTensor<U>
    where
        TaskScope: DotKernel<T, U>,
    {
        let raw = dot_along_dim_view(self.raw.as_view(), scalars.raw.as_view(), dim);
        DeviceTensor { raw }
    }
}

unsafe impl DotKernel<SP1Field, SP1Field> for TaskScope {
    fn partial_dot_kernel_last_dim() -> KernelPtr {
        unsafe { partial_dot_koala_bear_kernel() }
    }

    fn dot_along_short_dimension_kernel() -> KernelPtr {
        unsafe { dot_along_short_dimension_kernel_koala_bear_base_base() }
    }
}

unsafe impl DotKernel<SP1ExtensionField, SP1ExtensionField> for TaskScope {
    fn partial_dot_kernel_last_dim() -> KernelPtr {
        unsafe { partial_dot_koala_bear_extension_kernel() }
    }

    fn dot_along_short_dimension_kernel() -> KernelPtr {
        unsafe { dot_along_short_dimension_kernel_koala_bear_extension_extension() }
    }
}

unsafe impl DotKernel<SP1Field, SP1ExtensionField> for TaskScope {
    fn partial_dot_kernel_last_dim() -> KernelPtr {
        unsafe { partial_dot_koala_bear_base_extension_kernel() }
    }

    fn dot_along_short_dimension_kernel() -> KernelPtr {
        unsafe { dot_along_short_dimension_kernel_koala_bear_base_extension() }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use slop_algebra::AbstractField;
    use slop_tensor::Tensor;
    use sp1_primitives::{SP1ExtensionField, SP1Field};

    use super::DeviceTensor;

    type SP1FieldExt = SP1ExtensionField;

    #[test]
    fn test_koala_bear_dot() {
        let num_summands = 100;
        let mut rng = rand::thread_rng();

        for size in [10, 100, 1 << 16] {
            let tensor = Tensor::<SP1Field>::rand(&mut rng, [num_summands, size]);
            let scalars = Tensor::<SP1Field>::rand(&mut rng, [size]);

            let inner_product = crate::run_sync_in_place(|t| {
                let device_tensor = DeviceTensor::from_host(&tensor, &t).unwrap();
                let device_scalars = DeviceTensor::from_host(&scalars, &t).unwrap();
                let inner_product = device_tensor.dot_along_dim(&device_scalars, 1);
                inner_product.to_host().unwrap()
            })
            .unwrap();

            assert_eq!(inner_product.sizes(), [num_summands]);
            for i in 0..num_summands {
                let expected_inner_product: SP1Field = tensor
                    .get(i)
                    .unwrap()
                    .as_slice()
                    .iter()
                    .copied()
                    .zip_eq(scalars.as_buffer().iter().copied())
                    .map(|(a, b)| a * b)
                    .sum();
                assert_eq!(expected_inner_product, *inner_product[[i]]);
            }
        }
    }

    #[test]
    fn test_koala_bear_extension_dot() {
        let num_summands = 100;
        let mut rng = rand::thread_rng();

        type EF = SP1ExtensionField;

        for size in [10, 100, 1 << 16] {
            let tensor = Tensor::<EF>::rand(&mut rng, [num_summands, size]);
            let scalars = Tensor::<EF>::rand(&mut rng, [size]);

            let inner_product = crate::run_sync_in_place(|t| {
                let device_tensor = DeviceTensor::from_host(&tensor, &t).unwrap();
                let device_scalars = DeviceTensor::from_host(&scalars, &t).unwrap();
                let inner_product = device_tensor.dot_along_dim(&device_scalars, 1);
                inner_product.to_host().unwrap()
            })
            .unwrap();

            assert_eq!(inner_product.sizes(), [num_summands]);
            for i in 0..num_summands {
                let expected_inner_product: EF = tensor
                    .get(i)
                    .unwrap()
                    .as_slice()
                    .iter()
                    .copied()
                    .zip_eq(scalars.as_buffer().iter().copied())
                    .map(|(a, b)| a * b)
                    .sum();
                assert_eq!(expected_inner_product, *inner_product[[i]]);
            }
        }
    }

    #[test]
    fn test_koala_bear_base_extension_dot() {
        let mut rng = rand::thread_rng();

        type F = SP1Field;
        type EF = SP1ExtensionField;

        for size in [10, 100, 1 << 10, 1 << 12, 1 << 16] {
            for num_summands in [64, 128] {
                let tensor = Tensor::<F>::rand(&mut rng, [num_summands, size]);
                let scalars = Tensor::<EF>::rand(&mut rng, [size]);

                let inner_product = crate::run_sync_in_place(|t| {
                    let device_tensor = DeviceTensor::from_host(&tensor, &t).unwrap();
                    let device_scalars = DeviceTensor::from_host(&scalars, &t).unwrap();
                    t.synchronize_blocking().unwrap();
                    let time = std::time::Instant::now();
                    let inner_product = device_tensor.dot_along_dim(&device_scalars, 1);
                    t.synchronize_blocking().unwrap();
                    tracing::info!(
                        "Dot time for size {}, num_summands: {}, time: {:?}",
                        size,
                        num_summands,
                        time.elapsed()
                    );
                    inner_product.to_host().unwrap()
                })
                .unwrap();

                assert_eq!(inner_product.sizes(), [num_summands]);
                for i in 0..num_summands {
                    let expected_inner_product: EF = tensor
                        .get(i)
                        .unwrap()
                        .as_slice()
                        .iter()
                        .copied()
                        .zip_eq(scalars.as_buffer().iter().copied())
                        .map(|(a, b)| b * a)
                        .sum();
                    assert_eq!(expected_inner_product, *inner_product[[i]]);
                }
            }
        }
    }

    #[test]
    fn test_dot_along_dim_0_base_base() {
        let mut rng = rand::thread_rng();

        let width = 10;
        let height = 1500;

        let host_tensor = Tensor::<SP1Field>::rand(&mut rng, [width, height]);
        let host_scalars = Tensor::<SP1Field>::rand(&mut rng, [width]);

        let dot = crate::run_sync_in_place(|t| {
            let tensor = DeviceTensor::from_host(&host_tensor, &t).unwrap();
            let scalars = DeviceTensor::from_host(&host_scalars, &t).unwrap();
            let dot = tensor.dot_along_dim(&scalars, 0);
            dot.to_host().unwrap()
        })
        .unwrap();

        assert_eq!(dot.sizes(), [height]);
        for i in 0..height {
            let mut dot_product = SP1Field::zero();
            for j in 0..width {
                dot_product += *host_scalars[[j]] * *host_tensor[[j, i]];
            }
            assert_eq!(*dot[[i]], dot_product, "Dot product at index {i} is incorrect");
        }
    }

    #[test]
    fn test_dot_along_dim_0_base_ext() {
        let mut rng = rand::thread_rng();

        let width = 10;
        let height = 1500;

        let host_tensor = Tensor::<SP1Field>::rand(&mut rng, [width, height]);
        let host_scalars = Tensor::<SP1FieldExt>::rand(&mut rng, [width]);

        let dot = crate::run_sync_in_place(|t| {
            let tensor = DeviceTensor::from_host(&host_tensor, &t).unwrap();
            let scalars = DeviceTensor::from_host(&host_scalars, &t).unwrap();
            let dot = tensor.dot_along_dim(&scalars, 0);
            dot.to_host().unwrap()
        })
        .unwrap();

        assert_eq!(dot.sizes(), [height]);
        for i in 0..height {
            let mut dot_product = SP1FieldExt::zero();
            for j in 0..width {
                dot_product += *host_scalars[[j]] * *host_tensor[[j, i]];
            }
            assert_eq!(*dot[[i]], dot_product, "Dot product at index {i} is incorrect");
        }
    }

    #[test]
    fn test_dot_along_dim_0_ext_ext() {
        let mut rng = rand::thread_rng();

        let width = 10;
        let height = 1500;

        let host_tensor = Tensor::<SP1FieldExt>::rand(&mut rng, [width, height]);
        let host_scalars = Tensor::<SP1FieldExt>::rand(&mut rng, [width]);

        let dot = crate::run_sync_in_place(|t| {
            let tensor = DeviceTensor::from_host(&host_tensor, &t).unwrap();
            let scalars = DeviceTensor::from_host(&host_scalars, &t).unwrap();
            let dot = tensor.dot_along_dim(&scalars, 0);
            dot.to_host().unwrap()
        })
        .unwrap();

        assert_eq!(dot.sizes(), [height]);
        for i in 0..height {
            let mut dot_product = SP1FieldExt::zero();
            for j in 0..width {
                dot_product += *host_scalars[[j]] * *host_tensor[[j, i]];
            }
            assert_eq!(*dot[[i]], dot_product, "Dot product at index {i} is incorrect");
        }
    }
}
