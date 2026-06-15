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
    /// Number of *columns* of preprocessed padding between the chip prep
    /// section and the chip main section in the jagged structure. Equal to
    /// `cols_so_far - Σ chip_prep_widths` after the prep section is
    /// generated; both construction paths (real `jagged_tracegen` and
    /// `from_chip_layout`) record this explicitly so consumers don't have
    /// to guess from `preprocessed_padding` (which is in *element* units).
    /// The real tracegen path can emit more than one such column when the
    /// "fill to next stacking-multiple" loop allocates several.
    pub prep_padding_col_count: usize,
    /// Number of *columns* of main padding at the tail of the jagged
    /// structure. Set after the main section is generated.
    pub main_padding_col_count: usize,
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

/// Abstract description of a chip layout used to build [`TraceDenseData`] / [`JaggedTraceMle`].
/// Each tuple is`(chip_name, preprocessed_width, main_width)` for one chip;
pub struct AbstractChipLayout(Vec<(String, usize, usize)>);

impl AbstractChipLayout {
    pub fn new(entries: Vec<(String, usize, usize)>) -> Self {
        Self(entries)
    }

    pub fn entries(&self) -> &[(String, usize, usize)] {
        &self.0
    }
}

/// Like [`AbstractChipLayout`], but with a per-chip row count attached to each entry.
/// Each tuple is `(chip_name, preprocessed_width, main_width, height)` for one chip.
pub struct AbstractChipLayoutWithHeights(Vec<(String, usize, usize, usize)>);

impl AbstractChipLayoutWithHeights {
    pub fn new(entries: Vec<(String, usize, usize, usize)>) -> Self {
        Self(entries)
    }

    pub fn entries(&self) -> &[(String, usize, usize, usize)] {
        &self.0
    }

    /// Chip names in layout order.
    pub fn chip_names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(name, _, _, _)| name.as_str())
    }
}

impl<F: Field> TraceDenseData<F, CpuBackend> {
    /// Build a `TraceDenseData` over a pre-allocated `dense` buffer using an
    /// [`AbstractChipLayoutWithHeights`].
    ///
    /// The `dense` buffer must be sized as `padded_preprocessed + padded_main`, where
    /// each section is the unpadded total rounded up to the next multiple of
    /// `2^log_stacking_height`.
    pub fn from_chip_layout(
        dense: Buffer<F, CpuBackend>,
        layout: &AbstractChipLayoutWithHeights,
        log_stacking_height: u32,
    ) -> Self {
        let stacking = 1usize << log_stacking_height;

        let total_preprocessed: usize = layout.0.iter().map(|(_, p, _, h)| p * h).sum();
        let total_main: usize = layout.0.iter().map(|(_, _, m, h)| m * h).sum();

        // note that this makes sure there is always at least one main and one preprocessed column
        let padded_preprocessed = total_preprocessed.next_multiple_of(stacking).max(stacking);
        let padded_main = total_main.next_multiple_of(stacking).max(stacking);

        assert_eq!(
            dense.len(),
            padded_preprocessed + padded_main,
            "dense buffer length must equal padded_preprocessed + padded_main",
        );

        let preprocessed_cols: usize = layout.0.iter().map(|(_, p, _, _)| p).sum();

        let mut preprocessed_table_index = BTreeMap::new();
        let mut main_table_index = BTreeMap::new();
        let mut preprocessed_ptr = 0usize;
        let mut main_ptr = padded_preprocessed;
        for (name, prep_w, main_w, h) in layout.0.iter() {
            let prep_lo = preprocessed_ptr;
            let prep_hi = prep_lo + h * prep_w;
            preprocessed_table_index.insert(
                name.clone(),
                TraceOffset { dense_offset: prep_lo..prep_hi, poly_size: *h, num_polys: *prep_w },
            );
            preprocessed_ptr = prep_hi;

            let main_lo = main_ptr;
            let main_hi = main_lo + h * main_w;
            main_table_index.insert(
                name.clone(),
                TraceOffset { dense_offset: main_lo..main_hi, poly_size: *h, num_polys: *main_w },
            );
            main_ptr = main_hi;
        }

        let preprocessed_padding = padded_preprocessed - total_preprocessed;
        let main_padding = padded_main - total_main;
        TraceDenseData {
            dense,
            preprocessed_offset: padded_preprocessed,
            preprocessed_cols,
            preprocessed_padding,
            main_padding,
            // `from_chip_layout` emits exactly one prep/main padding column
            // when the corresponding padding is non-zero (see
            // `JaggedTraceMle::from_chip_layout`).
            prep_padding_col_count: (preprocessed_padding > 0) as usize,
            main_padding_col_count: (main_padding > 0) as usize,
            preprocessed_table_index,
            main_table_index,
        }
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
        column_heights: Buffer<u32, B>,
    ) -> Self {
        JaggedTraceMle(JaggedMle::new(dense_data, col_index, start_indices, column_heights))
    }
}

impl<F: Field> JaggedTraceMle<F, CpuBackend> {
    /// Build a `JaggedTraceMle` over a pre-allocated `dense` buffer using a chip-layout
    /// description as parallel slices. Constructs the inner [`TraceDenseData`] with the
    /// same layout as [`TraceDenseData::from_chip_layout`], plus the jagged column
    /// metadata: one logical column per chip column for both preprocessed and main,
    /// plus one padding column per section that has nonzero padding.
    ///
    /// All heights must be even, since column heights and column-index entries
    /// are stored at half-element granularity.
    pub fn from_chip_layout(
        dense: Buffer<F, CpuBackend>,
        layout: &AbstractChipLayoutWithHeights,
        log_stacking_height: u32,
    ) -> Self {
        assert!(layout.0.iter().all(|(_, _, _, h)| h % 2 == 0), "heights must be even");

        let dense_data = TraceDenseData::from_chip_layout(dense, layout, log_stacking_height);

        let total_dense = dense_data.dense.len();
        let preprocessed_padding = dense_data.preprocessed_padding;
        let main_padding = dense_data.main_padding;

        let num_data_cols: usize = layout.0.iter().map(|(_, p, m, _)| p + m).sum();
        let num_cols =
            num_data_cols + (preprocessed_padding > 0) as usize + (main_padding > 0) as usize;

        let mut col_index = vec![0u32; total_dense / 2];
        let mut start_idx = vec![0u32; num_cols + 1];
        let mut column_heights: Vec<u32> = Vec::with_capacity(num_cols);

        let mut col: u32 = 0;
        let mut cnt: usize = 0;

        let mut emit = |w: usize, h: usize, col: &mut u32, cnt: &mut usize| {
            let half = h / 2;
            for _ in 0..w {
                col_index[*cnt..*cnt + half].fill(*col);
                *cnt += half;
                start_idx[*col as usize + 1] = start_idx[*col as usize] + half as u32;
                column_heights.push(half as u32);
                *col += 1;
            }
        };

        for (_, prep_w, _, h) in layout.0.iter() {
            emit(*prep_w, *h, &mut col, &mut cnt);
        }
        if preprocessed_padding > 0 {
            emit(1, preprocessed_padding, &mut col, &mut cnt);
        }
        for (_, _, main_w, h) in layout.0.iter() {
            emit(*main_w, *h, &mut col, &mut cnt);
        }
        if main_padding > 0 {
            emit(1, main_padding, &mut col, &mut cnt);
        }

        debug_assert_eq!(cnt, total_dense / 2);
        debug_assert_eq!(col as usize, num_cols);

        Self::new(
            dense_data,
            Buffer::from(col_index),
            Buffer::from(start_idx),
            Buffer::from(column_heights),
        )
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
            DeviceBuffer::from_host(&column_heights, t).unwrap().into_inner(),
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
            prep_padding_col_count: self.prep_padding_col_count,
            main_padding_col_count: self.main_padding_col_count,
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
        let column_heights_host = DeviceBuffer::from_raw(column_heights).to_host().unwrap().into();
        JaggedTraceMle::new(host_dense, col_index_host, start_indices_host, column_heights_host)
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
            prep_padding_col_count: self.prep_padding_col_count,
            main_padding_col_count: self.main_padding_col_count,
        }
    }
}
