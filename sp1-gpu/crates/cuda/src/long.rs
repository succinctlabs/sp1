use futures::prelude::*;
use slop_algebra::Field;
use slop_commit::Message;
use slop_tensor::TransposeBackend;

use slop_alloc::{CanCopyFrom, CopyIntoBackend, CpuBackend};
use slop_jagged::LongMle;

use crate::TaskScope;

impl<F: Field> CopyIntoBackend<TaskScope, CpuBackend> for LongMle<F, CpuBackend>
where
    TaskScope: TransposeBackend<F>,
{
    type Output = LongMle<F, TaskScope>;

    async fn copy_into_backend(
        self,
        backend: &TaskScope,
    ) -> Result<Self::Output, slop_alloc::mem::CopyError> {
        let log_stacking_height = self.log_stacking_height();
        let components = stream::iter(self.into_components().into_iter())
            .then(|mle| async move { backend.copy_into(mle).await.unwrap() })
            .collect::<Message<_>>()
            .await;
        Ok(LongMle::new(components, log_stacking_height))
    }
}

impl<F: Field> CopyIntoBackend<CpuBackend, TaskScope> for LongMle<F, TaskScope>
where
    TaskScope: TransposeBackend<F>,
{
    type Output = LongMle<F, CpuBackend>;

    async fn copy_into_backend(
        self,
        backend: &CpuBackend,
    ) -> Result<Self::Output, slop_alloc::mem::CopyError> {
        let log_stacking_height = self.log_stacking_height();
        let components = stream::iter(self.into_components().into_iter())
            .then(|mle| async move { backend.copy_into(mle).await.unwrap() })
            .collect::<Message<_>>()
            .await;
        Ok(LongMle::new(components, log_stacking_height))
    }
}
