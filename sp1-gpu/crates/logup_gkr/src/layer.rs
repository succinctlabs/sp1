use slop_alloc::{Backend, HasBackend};
use slop_tensor::Tensor;
use sp1_gpu_cudart::TaskScope;

use sp1_gpu_utils::{DenseData, DenseDataMut, Ext, Felt};

/// A layer of the GKR circuit.
///
/// This layer contains the polynomials p_0, p_1, q_0, q_1 in evaluation form.
#[derive(Clone)]
pub struct JaggedGkrLayer<A: Backend = TaskScope> {
    /// The layer data, stored as a tensor of shape [4, 1, 2 * height].
    pub layer: Tensor<Ext, A>,
    /// Half of the height of the layer.
    pub height: usize,
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
        Self { layer, height }
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
        Self { numerator, denominator, height }
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
