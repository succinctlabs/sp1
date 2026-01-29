use slop_algebra::UnivariatePolynomial;
use slop_alloc::{Buffer, CpuBackend};
use slop_tensor::Tensor;
use sp1_primitives::{SP1ExtensionField, SP1Field};

use crate::TaskScope;

pub trait CudaSend: Send {
    /// Change the scope of the item to a new one.
    ///
    /// # Safety
    unsafe fn send_to_scope(self, scope: &TaskScope) -> Self;
}

impl<T: CudaSend> CudaSend for Option<T> {
    #[inline]
    unsafe fn send_to_scope(self, scope: &TaskScope) -> Self {
        self.map(|t| t.send_to_scope(scope))
    }
}

impl<T> CudaSend for Buffer<T, TaskScope> {
    #[inline]
    unsafe fn send_to_scope(mut self, scope: &TaskScope) -> Self {
        *self.allocator_mut() = scope.clone();
        self
    }
}

impl<T> CudaSend for Tensor<T, TaskScope> {
    #[inline]
    unsafe fn send_to_scope(self, scope: &TaskScope) -> Self {
        let Tensor { storage, dimensions } = self;
        let storage = storage.send_to_scope(scope);
        Tensor { storage, dimensions }
    }
}

impl<T> CudaSend for Tensor<T, CpuBackend> {
    #[inline]
    unsafe fn send_to_scope(self, _scope: &TaskScope) -> Self {
        self
    }
}

impl<T: CudaSend> CudaSend for UnivariatePolynomial<T> {
    #[inline]
    unsafe fn send_to_scope(self, _scope: &TaskScope) -> Self {
        self
    }
}

macro_rules! scopeless_send_impl {
    ($($t:ty)*) => {
        $(
            impl CudaSend for $t {
                #[inline]
                unsafe fn send_to_scope(self, _scope: &TaskScope) -> Self {
                    self
                }
            }
        )*
    }
}

scopeless_send_impl!(() u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize f32 f64);
scopeless_send_impl!(SP1Field);
scopeless_send_impl!(SP1ExtensionField);

macro_rules! tuple_cuda_send_impl {
    ($(($($T:ident),+)),*) => {
        $(
            #[allow(non_snake_case)]
            impl<$($T: CudaSend),+> CudaSend for ($($T,)+) {
                #[inline]
                unsafe fn send_to_scope(self, scope: &TaskScope) -> Self {
                    let ($($T,)+) = self;
                    ($($T.send_to_scope(scope),)+)
                }
            }
        )*
    }
}

tuple_cuda_send_impl! {
    (T1),
    (T1, T2),
    (T1, T2, T3),
    (T1, T2, T3, T4),
    (T1, T2, T3, T4, T5),
    (T1, T2, T3, T4, T5, T6),
    (T1, T2, T3, T4, T5, T6, T7),
    (T1, T2, T3, T4, T5, T6, T7, T8),
    (T1, T2, T3, T4, T5, T6, T7, T8, T9),
    (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10),
    (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11),
    (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)
}
