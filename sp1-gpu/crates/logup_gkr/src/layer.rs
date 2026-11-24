use std::sync::Arc;

use slop_alloc::{Backend, Buffer, HasBackend};
use slop_tensor::Tensor;
use sp1_gpu_cudart::{DeviceBuffer, TaskScope};

use sp1_gpu_utils::{DenseData, DenseDataMut, Ext, Felt};

/// Column lengths follow the same recurrence in the circuit and in every sumcheck.
#[derive(Clone, Default)]
pub(crate) struct FoldLayouts(Option<Arc<FoldLayout>>);

struct FoldLayout {
    starts: Buffer<u32, TaskScope>,
    heights: Buffer<u32, TaskScope>,
    total: u32,
    next: FoldLayouts,
}

impl FoldLayouts {
    pub(crate) fn new(initial: &[u32], rounds: u32, backend: &TaskScope) -> Self {
        let mut heights = initial.to_vec();
        let mut layouts = Vec::with_capacity(rounds as usize);
        for _ in 0..rounds {
            for h in &mut heights {
                *h = h.div_ceil(4) * 2;
            }
            let mut starts = Vec::with_capacity(heights.len() + 1);
            starts.push(0);
            let mut total = 0;
            for h in &heights {
                total += h;
                starts.push(total);
            }
            layouts.push((
                DeviceBuffer::from_host_slice(&starts, backend).unwrap().into_inner(),
                DeviceBuffer::from_host_slice(&heights, backend).unwrap().into_inner(),
                total,
            ));
        }
        layouts.into_iter().rev().fold(Self::default(), |next, (starts, heights, total)| {
            Self(Some(Arc::new(FoldLayout { starts, heights, total, next })))
        })
    }

    pub(crate) fn after(
        &self,
        rounds: usize,
        heights: &Buffer<u32, TaskScope>,
    ) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>, u32, Self) {
        let mut cursor = self;
        for _ in 1..rounds {
            if let Some(layout) = &cursor.0 {
                cursor = &layout.next;
            }
        }
        if let Some(layout) = &cursor.0 {
            return (
                layout.starts.clone(),
                layout.heights.clone(),
                layout.total,
                layout.next.clone(),
            );
        }
        // A standalone layer constructed from device buffers may have no host layout.
        let (mut starts, mut next_heights, mut total) =
            sp1_gpu_utils::fold_jagged_metadata_dev(heights);
        for _ in 1..rounds {
            (starts, next_heights, total) = sp1_gpu_utils::fold_jagged_metadata_dev(&next_heights);
        }
        (starts, next_heights, total, Self::default())
    }
}

/// A layer of the GKR circuit.
///
/// This layer contains the polynomials p_0, p_1, q_0, q_1 in evaluation form.
#[derive(Clone)]
pub struct JaggedGkrLayer<A: Backend = TaskScope> {
    /// The layer data, stored as a tensor of shape [4, 1, 2 * height].
    pub layer: Tensor<Ext, A>,
    /// Half of the height of the layer.
    pub height: usize,
    pub(crate) folds: FoldLayouts,
}

/// The raw pointer equivalent of [`JaggedGkrLayer`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedGkrLayerRaw {
    layer: *const Ext,
    height: usize,
}

/// The mutable raw pointer equivalent of [`JaggedGkrLayer`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedGkrLayerMutRaw {
    layer: *mut Ext,
    height: usize,
}

impl<A: Backend> JaggedGkrLayer<A> {
    #[inline]
    pub fn new(layer: Tensor<Ext, A>, height: usize) -> Self {
        Self { layer, height, folds: FoldLayouts::default() }
    }

    #[inline]
    pub unsafe fn assume_init(&mut self) {
        self.layer.assume_init();
    }

    #[inline]
    pub fn into_parts(self) -> (Tensor<Ext, A>, usize) {
        (self.layer, self.height)
    }
}

impl<A: Backend> HasBackend for JaggedGkrLayer<A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        self.layer.backend()
    }
}

impl<A: Backend> DenseData<A> for JaggedGkrLayer<A> {
    type DenseDataRaw = JaggedGkrLayerRaw;
    fn as_ptr(&self) -> Self::DenseDataRaw {
        JaggedGkrLayerRaw { layer: self.layer.as_ptr(), height: self.height }
    }
}

impl<A: Backend> DenseDataMut<A> for JaggedGkrLayer<A> {
    type DenseDataMutRaw = JaggedGkrLayerMutRaw;
    fn as_mut_ptr(&mut self) -> Self::DenseDataMutRaw {
        JaggedGkrLayerMutRaw { layer: self.layer.as_mut_ptr(), height: self.height }
    }
}

/// The first layer of the GKR circuit. This is a special case because the numerator is Felts, and the denominator is Ext.
pub struct JaggedFirstGkrLayer<A: Backend> {
    /// The numerator of the first layer. Has sizes [2, 1, 2 * height].
    pub numerator: Tensor<Felt, A>,
    /// The denominator of the first layer. Has sizes [2, 1, 2 * height].
    pub denominator: Tensor<Ext, A>,
    /// Half of the real height of the layer.
    pub height: usize,
    pub(crate) folds: FoldLayouts,
}

/// The raw pointer equivalent of [`JaggedFirstGkrLayer`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedFirstGkrLayerRaw {
    numerator: *const Felt,
    denominator: *const Ext,
    height: usize,
}

/// The mutable raw pointer equivalent of [`JaggedFirstGkrLayer`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedFirstGkrLayerMutRaw {
    numerator: *mut Felt,
    denominator: *mut Ext,
    height: usize,
}

impl<A: Backend> JaggedFirstGkrLayer<A> {
    #[inline]
    pub fn new(numerator: Tensor<Felt, A>, denominator: Tensor<Ext, A>, height: usize) -> Self {
        Self { numerator, denominator, height, folds: FoldLayouts::default() }
    }

    #[inline]
    pub unsafe fn assume_init(&mut self) {
        self.numerator.assume_init();
        self.denominator.assume_init();
    }

    #[inline]
    pub fn into_parts(self) -> (Tensor<Felt, A>, Tensor<Ext, A>, usize) {
        (self.numerator, self.denominator, self.height)
    }
}

impl<A: Backend> HasBackend for JaggedFirstGkrLayer<A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        self.numerator.backend()
    }
}

impl<A: Backend> DenseData<A> for JaggedFirstGkrLayer<A> {
    type DenseDataRaw = JaggedFirstGkrLayerRaw;
    fn as_ptr(&self) -> Self::DenseDataRaw {
        JaggedFirstGkrLayerRaw {
            numerator: self.numerator.as_ptr(),
            denominator: self.denominator.as_ptr(),
            height: self.height,
        }
    }
}

impl<A: Backend> DenseDataMut<A> for JaggedFirstGkrLayer<A> {
    type DenseDataMutRaw = JaggedFirstGkrLayerMutRaw;
    fn as_mut_ptr(&mut self) -> Self::DenseDataMutRaw {
        JaggedFirstGkrLayerMutRaw {
            numerator: self.numerator.as_mut_ptr(),
            denominator: self.denominator.as_mut_ptr(),
            height: self.height,
        }
    }
}
