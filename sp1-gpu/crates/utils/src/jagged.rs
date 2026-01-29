use std::iter::once;

use slop_alloc::{Backend, Buffer, HasBackend};
use slop_tensor::{Dimensions, Tensor};
use sp1_gpu_cudart::TaskScope;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct JaggedMle<D: DenseData<A>, A: Backend> {
    /// col_index[i / 2] is the column that the i'th element of the dense data belongs to.
    pub col_index: Buffer<u32, A>,
    /// start_indices[i] is the half the dense index of the first element of the i'th column.
    pub start_indices: Buffer<u32, A>,
    /// column_heights[i] is half of the height of the i'th column.
    pub column_heights: Vec<u32>,
    pub dense_data: D,
}

pub struct VirtualTensor<T, B: Backend> {
    pub data: *const T,
    pub sizes: Dimensions,
    pub backend: B,
}

impl<T, B: Backend> VirtualTensor<T, B> {
    pub fn new(data: *const T, sizes: Dimensions, backend: B) -> Self {
        Self { data, sizes, backend }
    }

    pub fn sizes(&self) -> &[usize] {
        self.sizes.sizes()
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn as_ptr(&self) -> *const T {
        self.data
    }

    pub fn from_tensor(tensor: &Tensor<T, B>) -> Self {
        Self {
            data: tensor.as_ptr(),
            sizes: tensor.shape().clone(),
            backend: tensor.backend().clone(),
        }
    }
}

pub trait DenseData<A: Backend> {
    type DenseDataRaw;
    fn as_ptr(&self) -> Self::DenseDataRaw;
}

pub trait DenseDataMut<A: Backend>: DenseData<A> {
    type DenseDataMutRaw;
    fn as_mut_ptr(&mut self) -> Self::DenseDataMutRaw;
}

/// The raw pointer equivalent of [`JaggedMle`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedMleRaw<D: DenseData<A>, A: Backend> {
    col_index: *const u32,
    start_indices: *const u32,
    dense_data: D::DenseDataRaw,
}

/// The mutable raw pointer equivalent of [`JaggedMle`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedMleMutRaw<D: DenseDataMut<A>, A: Backend> {
    col_index: *mut u32,
    start_indices: *mut u32,
    dense_data: D::DenseDataMutRaw,
}

impl<D: DenseData<A>, A: Backend> JaggedMle<D, A> {
    pub fn as_raw(&self) -> JaggedMleRaw<D, A> {
        JaggedMleRaw {
            col_index: self.col_index.as_ptr(),
            start_indices: self.start_indices.as_ptr(),
            dense_data: self.dense_data.as_ptr(),
        }
    }

    pub fn as_mut_raw(&mut self) -> JaggedMleMutRaw<D, A>
    where
        D: DenseDataMut<A>,
    {
        JaggedMleMutRaw {
            col_index: self.col_index.as_mut_ptr(),
            start_indices: self.start_indices.as_mut_ptr(),
            dense_data: self.dense_data.as_mut_ptr(),
        }
    }

    pub fn new(
        dense_data: D,
        col_index: Buffer<u32, A>,
        start_indices: Buffer<u32, A>,
        column_heights: Vec<u32>,
    ) -> Self {
        Self { dense_data, col_index, start_indices, column_heights }
    }

    pub fn dense(&self) -> &D {
        &self.dense_data
    }

    pub fn dense_mut(&mut self) -> &mut D {
        &mut self.dense_data
    }

    pub fn col_index(&self) -> &Buffer<u32, A> {
        &self.col_index
    }

    pub fn col_index_mut(&mut self) -> &mut Buffer<u32, A> {
        &mut self.col_index
    }

    pub fn start_indices(&self) -> &Buffer<u32, A> {
        &self.start_indices
    }

    pub fn start_indices_mut(&mut self) -> &mut Buffer<u32, A> {
        &mut self.start_indices
    }

    pub fn into_parts(self) -> (D, Buffer<u32, A>, Buffer<u32, A>) {
        (self.dense_data, self.col_index, self.start_indices)
    }
}

impl<D: DenseData<TaskScope>> JaggedMle<D, TaskScope> {
    /// Computes the next start indices and column heights for use in jagged fix last variable.
    ///
    /// TODO: ignore all of the padding stuff.
    pub fn next_start_indices_and_column_heights(&self) -> (Buffer<u32>, Vec<u32>) {
        let output_heights =
            self.column_heights.iter().map(|height| height.div_ceil(4) * 2).collect::<Vec<u32>>();

        let new_start_idx = once(0)
            .chain(output_heights.iter().scan(0u32, |acc, x| {
                *acc += x;
                Some(*acc)
            }))
            .collect::<Vec<_>>();
        let buffer_start_idx = Buffer::from(new_start_idx);
        (buffer_start_idx, output_heights)
    }
}

impl<D: DenseData<A>, A: Backend> HasBackend for JaggedMle<D, A> {
    type Backend = A;
    fn backend(&self) -> &A {
        self.col_index.backend()
    }
}
