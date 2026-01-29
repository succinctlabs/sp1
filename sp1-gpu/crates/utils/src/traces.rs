use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut, Range};

use slop_algebra::Field;
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend};
use slop_tensor::{Dimensions, Tensor, TensorView};
use sp1_gpu_cudart::{DeviceBuffer, TaskScope};

use crate::jagged::JaggedMle;
use crate::{DenseData, DenseDataMut};

#[derive(Clone, Debug)]
pub struct TraceOffset {
    /// Dense data offset.
    pub dense_offset: Range<usize>,
    /// The size of each polynomial in this trace.
    pub poly_size: usize,
    /// Number of polynomials in this trace.
    pub num_polys: usize,
}

#[derive(Clone)]
pub struct JaggedTraceMle<F: Field, B: Backend>(pub JaggedMle<TraceDenseData<F, B>, B>);

impl<F: Field, B: Backend> HasBackend for JaggedTraceMle<F, B> {
    type Backend = B;
    fn backend(&self) -> &B {
        self.0.backend()
    }
}

impl<F: Field, B: Backend> Deref for JaggedTraceMle<F, B> {
    type Target = JaggedMle<TraceDenseData<F, B>, B>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Field, B: Backend> DerefMut for JaggedTraceMle<F, B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Jagged representation of the traces.
#[derive(Clone, Debug)]
pub struct TraceDenseData<F: Field, B: Backend> {
    /// The dense representation of the traces.
    pub dense: Buffer<F, B>,
    /// The dense offset of the preprocessed traces.
    pub preprocessed_offset: usize,
    /// The total number of columns in the preprocessed traces.
    pub preprocessed_cols: usize,
    /// The amount of preprocessed padding, to the next multiple of 2^log_stacking_height.
    pub preprocessed_padding: usize,
    /// The amount of main padding, to the next multiple of 2^log_stacking_height.
    pub main_padding: usize,
    /// A mapping from chip name to the range of dense data it occupies for preprocessed traces.
    pub preprocessed_table_index: BTreeMap<String, TraceOffset>,
    /// A mapping from chip name to the range of dense data it occupies for main traces.
    pub main_table_index: BTreeMap<String, TraceOffset>,
}

impl<F: Field, B: Backend> TraceDenseData<F, B> {
    pub fn main_virtual_tensor(&'_ self, log_stacking_height: u32) -> TensorView<'_, F, B> {
        let ptr = unsafe { self.dense.as_ptr().add(self.preprocessed_offset) };
        let sizes = Dimensions::try_from([
            self.main_size() / (1 << log_stacking_height),
            1 << log_stacking_height,
        ])
        .unwrap();
        // This is safe because we inherit the lifetime of self and the offset should be valid.
        unsafe { TensorView::from_raw_parts(ptr, sizes, self.backend().clone()) }
    }

    /// Copies the correct data from dense to a new tensor for main traces.
    pub fn main_tensor(&self, log_stacking_height: u32) -> Tensor<F, B> {
        let mut tensor = Tensor::with_sizes_in(
            [self.main_size() / (1 << log_stacking_height), 1 << log_stacking_height],
            self.backend().clone(),
        );
        let backend = self.dense.backend();
        unsafe {
            tensor.assume_init();
            tensor
                .as_mut_buffer()
                .copy_from_slice(&self.dense[self.preprocessed_offset..], backend)
                .unwrap();
        }
        tensor
    }

    pub fn preprocessed_virtual_tensor(&'_ self, log_stacking_height: u32) -> TensorView<'_, F, B> {
        let ptr = self.dense.as_ptr();
        let sizes = Dimensions::try_from([
            self.preprocessed_offset / (1 << log_stacking_height),
            1 << log_stacking_height,
        ])
        .unwrap();
        unsafe { TensorView::from_raw_parts(ptr, sizes, self.backend().clone()) }
    }

    /// Copies the correct data from dense to a new tensor for preprocessed traces.
    pub fn preprocessed_tensor(&self, log_stacking_height: u32) -> Tensor<F, B> {
        let mut tensor = Tensor::with_sizes_in(
            [self.preprocessed_offset / (1 << log_stacking_height), 1 << log_stacking_height],
            self.backend().clone(),
        );
        let backend = self.dense.backend();
        unsafe {
            tensor.assume_init();
            tensor
                .as_mut_buffer()
                .copy_from_slice(&self.dense[..self.preprocessed_offset], backend)
                .unwrap();
        }
        tensor
    }

    /// The size of the main polynomial.
    #[inline]
    pub fn main_poly_height(&self, name: &str) -> Option<usize> {
        self.main_table_index.get(name).map(|offset| offset.poly_size)
    }

    /// The size of the preprocessed polynomial.
    #[inline]
    pub fn preprocessed_poly_height(&self, name: &str) -> Option<usize> {
        self.preprocessed_table_index.get(name).map(|offset| offset.poly_size)
    }

    /// The number of polynomials in the main trace.
    #[inline]
    pub fn main_num_polys(&self, name: &str) -> Option<usize> {
        self.main_table_index.get(name).map(|offset| offset.num_polys)
    }

    /// The size of the main trace dense data, including padding.
    #[inline]
    pub fn main_size(&self) -> usize {
        self.dense.len() - self.preprocessed_offset
    }

    /// The number of polynomials in the preprocessed trace.
    #[inline]
    pub fn preprocessed_num_polys(&self, name: &str) -> Option<usize> {
        self.preprocessed_table_index.get(name).map(|offset| offset.num_polys)
    }
}

impl<F: Field, B: Backend> HasBackend for TraceDenseData<F, B> {
    type Backend = B;
    fn backend(&self) -> &B {
        self.dense.backend()
    }
}

impl<F: Field, B: Backend> JaggedTraceMle<F, B> {
    pub fn new(
        dense_data: TraceDenseData<F, B>,
        col_index: Buffer<u32, B>,
        start_indices: Buffer<u32, B>,
        column_heights: Vec<u32>,
    ) -> Self {
        JaggedTraceMle(JaggedMle::new(dense_data, col_index, start_indices, column_heights))
    }
}

impl<F: Field> JaggedTraceMle<F, TaskScope> {
    pub fn preprocessed_virtual_tensor(
        &'_ self,
        log_stacking_height: u32,
    ) -> TensorView<'_, F, TaskScope> {
        self.dense_data.preprocessed_virtual_tensor(log_stacking_height)
    }

    pub fn main_virtual_tensor(&'_ self, log_stacking_height: u32) -> TensorView<'_, F, TaskScope> {
        self.dense_data.main_virtual_tensor(log_stacking_height)
    }

    pub fn main_poly_height(&self, name: &str) -> Option<usize> {
        self.dense_data.main_poly_height(name)
    }

    pub fn preprocessed_poly_height(&self, name: &str) -> Option<usize> {
        self.dense_data.preprocessed_poly_height(name)
    }

    pub fn main_num_polys(&self, name: &str) -> Option<usize> {
        self.dense_data.main_num_polys(name)
    }

    pub fn main_size(&self) -> usize {
        self.dense_data.main_size()
    }

    pub fn preprocessed_num_polys(&self, name: &str) -> Option<usize> {
        self.dense_data.preprocessed_num_polys(name)
    }
}

/// The raw pointer to the dense data, for use in CUDA FFI calls.
#[repr(C)]
pub struct TraceDenseDataRaw<F> {
    dense: *const F,
}

/// The raw pointer to the dense data, for use in CUDA FFI calls.
#[repr(C)]
pub struct TraceDenseDataMutRaw<F> {
    dense: *mut F,
}

impl<F: Field, B: Backend> DenseData<B> for TraceDenseData<F, B> {
    type DenseDataRaw = TraceDenseDataRaw<F>;

    fn as_ptr(&self) -> TraceDenseDataRaw<F> {
        TraceDenseDataRaw { dense: self.dense.as_ptr() }
    }
}

impl<F: Field, B: Backend> DenseDataMut<B> for TraceDenseData<F, B> {
    type DenseDataMutRaw = TraceDenseDataMutRaw<F>;

    fn as_mut_ptr(&mut self) -> TraceDenseDataMutRaw<F> {
        TraceDenseDataMutRaw { dense: self.dense.as_mut_ptr() }
    }
}

impl<F: Field> JaggedTraceMle<F, CpuBackend> {
    pub fn into_device(self, t: &TaskScope) -> JaggedTraceMle<F, TaskScope> {
        let JaggedMle { col_index, start_indices, column_heights, dense_data } = self.0;
        JaggedTraceMle::new(
            dense_data.into_device_in(t),
            DeviceBuffer::from_host(&col_index, t).unwrap().into_inner(),
            DeviceBuffer::from_host(&start_indices, t).unwrap().into_inner(),
            column_heights,
        )
    }
}

impl<F: Field> TraceDenseData<F, CpuBackend> {
    pub fn into_device_in(self, t: &TaskScope) -> TraceDenseData<F, TaskScope> {
        TraceDenseData {
            dense: DeviceBuffer::from_host(&self.dense, t).unwrap().into_inner(),
            preprocessed_offset: self.preprocessed_offset,
            preprocessed_cols: self.preprocessed_cols,
            preprocessed_table_index: self.preprocessed_table_index,
            main_table_index: self.main_table_index,
            preprocessed_padding: self.preprocessed_padding,
            main_padding: self.main_padding,
        }
    }
}

impl<F: Field> JaggedTraceMle<F, TaskScope> {
    pub fn into_host(self) -> JaggedTraceMle<F, CpuBackend> {
        let JaggedMle { col_index, start_indices, column_heights, dense_data } = self.0;
        let host_dense = dense_data.into_host();
        // Convert device buffers to host using DeviceBuffer wrapper
        let col_index_host = DeviceBuffer::from_raw(col_index).to_host().unwrap().into();
        let start_indices_host = DeviceBuffer::from_raw(start_indices).to_host().unwrap().into();
        JaggedTraceMle::new(host_dense, col_index_host, start_indices_host, column_heights)
    }
}

impl<F: Field> TraceDenseData<F, TaskScope> {
    pub fn into_host(self) -> TraceDenseData<F, CpuBackend> {
        let host_dense = DeviceBuffer::from_raw(self.dense).to_host().unwrap().into();
        TraceDenseData {
            dense: host_dense,
            preprocessed_offset: self.preprocessed_offset,
            preprocessed_cols: self.preprocessed_cols,
            preprocessed_table_index: self.preprocessed_table_index,
            main_table_index: self.main_table_index,
            preprocessed_padding: self.preprocessed_padding,
            main_padding: self.main_padding,
        }
    }
}
