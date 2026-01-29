use std::ffi::c_void;

use slop_tensor::{Dimensions, Tensor, TensorViewMut};
use sp1_gpu_sys::{
    reduce::{
        koala_bear_extension_sum_block_reduce_kernel,
        koala_bear_extension_sum_partial_block_reduce_kernel, koala_bear_sum_block_reduce_kernel,
        koala_bear_sum_partial_block_reduce_kernel,
    },
    runtime::{Dim3, KernelPtr},
};
use sp1_primitives::{SP1ExtensionField, SP1Field};

use crate::{args, DeviceCopy, DeviceTensor};

use super::TaskScope;

const MAX_NUM_FINAL_BLOCKS: usize = 2;

/// Kernels for performing a sum over a block or a partial sum over a grid to block sums.
///
/// # Safety
///
/// The implementor must ensure that the arguments of the kernels are laid out as expected by the
/// functions [block_sum] and [partial_sum_reduction] below.
pub unsafe trait DeviceSumKernel<T> {
    fn partial_sum_kernel() -> KernelPtr;

    fn block_sum_kernel() -> KernelPtr;
}

fn block_sum<T: DeviceCopy, const BLOCK_SIZE: usize, const INTIAL_STRIDE: usize>(
    src: &Tensor<T, TaskScope>,
    mut dst: TensorViewMut<T, TaskScope>,
    dim: usize,
) where
    TaskScope: DeviceSumKernel<T>,
{
    let height = src.sizes()[dim];
    let width = src.total_len() / height;

    let block_dim: Dim3 = BLOCK_SIZE.into();
    let num_reduce_blocks = height.div_ceil(block_dim.x as usize).div_ceil(INTIAL_STRIDE);
    let grid_dim: Dim3 = (num_reduce_blocks, width, 1).into();

    // If the height is small enough, we can use one kernel for the sum.
    let args = args!(src.as_ptr(), dst.as_mut_ptr(), width, height);
    let shared_mem = 0;
    unsafe {
        src.backend()
            .launch_kernel(TaskScope::block_sum_kernel(), grid_dim, block_dim, &args, shared_mem)
            .unwrap();
    }
}

/// A general sum based reduction that allows a generic first step.
///
/// # Safety
#[inline]
pub unsafe fn partial_sum_reduction_into<
    T: DeviceCopy,
    const BLOCK_SIZE: usize,
    const INTIAL_STRIDE: usize,
    const NUM_ARGS: usize,
>(
    dst: TensorViewMut<T, TaskScope>,
    partial_reduction_kernel: KernelPtr,
    mut partial_args: [*mut c_void; NUM_ARGS],
    partial_shared_mem: usize,
    reduction_shape: &Dimensions,
    dim: usize,
    scope: &TaskScope,
) where
    TaskScope: DeviceSumKernel<T>,
{
    let height = reduction_shape.sizes()[dim];
    let width = reduction_shape.total_len() / height;

    let block_dim: Dim3 = BLOCK_SIZE.into();
    let num_reduce_blocks = height.div_ceil(block_dim.x as usize).div_ceil(INTIAL_STRIDE);
    let grid_dim: Dim3 = (num_reduce_blocks, width, 1).into();

    let mut sizes = reduction_shape.sizes().to_vec();
    sizes[dim] = grid_dim.x as usize;
    let mut partial_sums = Tensor::<T, _>::with_sizes_in(sizes.clone(), scope.clone());
    let num_tiles = block_dim.x.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * block_dim.y * (std::mem::size_of::<T>() as u32);
    let partial_args_ptr = &partial_sums.as_mut_ptr() as *const _ as *mut c_void;
    partial_args[0] = partial_args_ptr;
    let args = partial_args;
    unsafe {
        partial_sums.assume_init();
        scope
            .launch_kernel(
                partial_reduction_kernel,
                grid_dim,
                block_dim,
                &args,
                shared_mem as usize + partial_shared_mem,
            )
            .unwrap();
    }

    // Now we need to sum the partial sums. We will do it in an iterative manner until the length
    // is small enough to do the final summation in one kernel.
    let mut partial_sums = partial_sums;
    while sizes[dim] > MAX_NUM_FINAL_BLOCKS * BLOCK_SIZE {
        let height = sizes[dim];
        let block_dim: Dim3 = BLOCK_SIZE.into();
        let num_reduce_blocks = height.div_ceil(block_dim.x as usize).div_ceil(INTIAL_STRIDE);
        let grid_dim: Dim3 = (num_reduce_blocks, width, 1).into();

        sizes[dim] = grid_dim.x as usize;
        let mut current = Tensor::<T, _>::with_sizes_in(sizes.clone(), scope.clone());
        let args = args!(current.as_mut_ptr(), partial_sums.as_ptr(), width, height);
        let num_tiles = block_dim.x.checked_div(32).unwrap_or(1);
        let shared_mem = num_tiles * block_dim.y * (std::mem::size_of::<T>() as u32);
        unsafe {
            current.assume_init();
            scope
                .launch_kernel(
                    TaskScope::partial_sum_kernel(),
                    grid_dim,
                    block_dim,
                    &args,
                    shared_mem as usize,
                )
                .unwrap();
        }
        // sizes[dim] = num_reduce_blocks;
        partial_sums = current;
    }

    // Now we need to sum the partial sums so we will use the block sum function.
    block_sum::<T, BLOCK_SIZE, INTIAL_STRIDE>(&partial_sums, dst, dim);
}

/// # Safety
pub unsafe fn partial_sum_reduction<
    T: DeviceCopy,
    const BLOCK_SIZE: usize,
    const INTIAL_STRIDE: usize,
    const NUM_ARGS: usize,
>(
    partial_reduction_kernel: KernelPtr,
    partial_args: [*mut c_void; NUM_ARGS],
    partial_shared_mem: usize,
    reduction_shape: &Dimensions,
    scope: &TaskScope,
    dim: usize,
) -> Tensor<T, TaskScope>
where
    TaskScope: DeviceSumKernel<T>,
{
    let mut sizes = reduction_shape.sizes().to_vec();
    sizes.remove(dim);
    let mut dst = Tensor::zeros_in(sizes, scope.clone());
    partial_sum_reduction_into::<T, BLOCK_SIZE, INTIAL_STRIDE, NUM_ARGS>(
        dst.as_view_mut(),
        partial_reduction_kernel,
        partial_args,
        partial_shared_mem,
        reduction_shape,
        dim,
        scope,
    );
    dst
}

impl<T: DeviceCopy> DeviceTensor<T>
where
    TaskScope: DeviceSumKernel<T>,
{
    pub fn sum_dim(&self, dim: usize) -> DeviceTensor<T> {
        let src = &self.raw;
        let mut sizes = src.sizes().to_vec();
        sizes.remove(dim);
        let mut dst = Tensor::zeros_in(sizes, src.backend().clone());
        const BLOCK_SIZE: usize = 512;
        const INTIAL_STRIDE: usize = 8;
        assert!(dim == src.sizes().len() - 1, "only summing over the last dimension is supported");

        let height = src.sizes()[dim];
        let width = src.total_len() / height;

        if height <= BLOCK_SIZE {
            block_sum::<T, BLOCK_SIZE, INTIAL_STRIDE>(src, dst.as_view_mut(), dim);
            return DeviceTensor { raw: dst };
        }

        // If the number of elements to sum is bigger than the block size, we need to use a two
        // step reduction.
        // 1. Partial sum: sum the elements in blocks of size BLOCK_SIZE
        // 2. Block sum: sum the partial sums in blocks of size BLOCK_SIZE

        let null_ptr = std::ptr::null::<c_void>();
        let partial_args = args!(null_ptr, src.as_ptr(), width, height);
        unsafe {
            partial_sum_reduction_into::<T, BLOCK_SIZE, INTIAL_STRIDE, 4>(
                dst.as_view_mut(),
                TaskScope::partial_sum_kernel(),
                partial_args,
                0,
                &src.dimensions,
                dim,
                src.backend(),
            );
        }
        DeviceTensor { raw: dst }
    }
}

unsafe impl DeviceSumKernel<SP1Field> for TaskScope {
    fn partial_sum_kernel() -> KernelPtr {
        unsafe { koala_bear_sum_partial_block_reduce_kernel() }
    }

    fn block_sum_kernel() -> KernelPtr {
        unsafe { koala_bear_sum_block_reduce_kernel() }
    }
}

unsafe impl DeviceSumKernel<SP1ExtensionField> for TaskScope {
    fn partial_sum_kernel() -> KernelPtr {
        unsafe { koala_bear_extension_sum_partial_block_reduce_kernel() }
    }

    fn block_sum_kernel() -> KernelPtr {
        unsafe { koala_bear_extension_sum_block_reduce_kernel() }
    }
}

#[cfg(test)]
mod tests {
    use slop_tensor::Tensor;
    use sp1_primitives::{SP1ExtensionField, SP1Field};

    use super::DeviceTensor;

    #[test]
    fn test_koala_bear_sum() {
        let num_summands = 100;
        let mut rng = rand::thread_rng();

        for size in [10, 100, 1 << 16] {
            let tensor = Tensor::<SP1Field>::rand(&mut rng, [num_summands, size]);

            let sum_tensor = crate::run_sync_in_place(|t| {
                let device_tensor = DeviceTensor::from_host(&tensor, &t).unwrap();
                let sums = device_tensor.sum_dim(1);
                sums.to_host().unwrap()
            })
            .unwrap();

            assert_eq!(sum_tensor.sizes(), [num_summands]);
            for i in 0..num_summands {
                let expected_sum: SP1Field =
                    tensor.get(i).unwrap().as_slice().iter().copied().sum();
                assert_eq!(expected_sum, *sum_tensor[[i]]);
            }
        }
    }

    #[test]
    fn test_koala_bear_ext_sum() {
        let num_summands = 128;
        let size = 1 << 16;
        let mut rng = rand::thread_rng();

        type EF = SP1ExtensionField;

        let tensor = Tensor::<EF>::rand(&mut rng, [num_summands, size]);

        let sum_tensor = crate::run_sync_in_place(|t| {
            let device_tensor = DeviceTensor::from_host(&tensor, &t).unwrap();
            let sums = device_tensor.sum_dim(1);
            sums.to_host().unwrap()
        })
        .unwrap();

        assert_eq!(sum_tensor.sizes(), [num_summands]);
        for i in 0..num_summands {
            let expected_sum: EF = tensor.get(i).unwrap().as_slice().iter().copied().sum();
            assert_eq!(expected_sum, *sum_tensor[[i]]);
        }
    }
}
