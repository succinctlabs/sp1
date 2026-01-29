// Async CopyIntoBackend/CopyToBackend impls removed - use sync DeviceMle/DeviceTensor methods instead

use crate::{sync::CudaSend, TaskScope};
use slop_multilinear::{Mle, MleEval, Point};

impl<T> CudaSend for Mle<T, TaskScope> {
    #[inline]
    unsafe fn send_to_scope(self, scope: &TaskScope) -> Self {
        let guts = self.into_guts().send_to_scope(scope);
        Mle::new(guts)
    }
}

impl<T> CudaSend for MleEval<T, TaskScope> {
    #[inline]
    unsafe fn send_to_scope(self, scope: &TaskScope) -> Self {
        let evaluations = self.into_evaluations().send_to_scope(scope);
        MleEval::new(evaluations)
    }
}

impl<T> CudaSend for Point<T, TaskScope> {
    #[inline]
    unsafe fn send_to_scope(self, scope: &TaskScope) -> Self {
        let values = self.into_values().send_to_scope(scope);
        Point::new(values)
    }
}
