// Async CopyIntoBackend impls removed - use sync DeviceTensor methods instead
// use slop_algebra::Field;
// use slop_alloc::{mem::CopyError, CopyIntoBackend, CpuBackend};
// use slop_basefold::RsCodeWord;
// use slop_tensor::TransposeBackend;
//
// use crate::TaskScope;
//
// impl<F: Field> CopyIntoBackend<CpuBackend, TaskScope> for RsCodeWord<F, TaskScope>
// where
//     TaskScope: TransposeBackend<F>,
// {
//     type Output = RsCodeWord<F, CpuBackend>;
//     async fn copy_into_backend(self, backend: &CpuBackend) -> Result<Self::Output, CopyError> {
//         // Transpose the values in the device since it's usually faster.
//         let tensor = self.data.transpose();
//         let data = tensor.copy_into_backend(backend).await?;
//         Ok(RsCodeWord::new(data))
//     }
// }
//
// impl<F: Field> CopyIntoBackend<TaskScope, CpuBackend> for RsCodeWord<F, CpuBackend>
// where
//     TaskScope: TransposeBackend<F>,
// {
//     type Output = RsCodeWord<F, TaskScope>;
//     async fn copy_into_backend(self, backend: &TaskScope) -> Result<Self::Output, CopyError> {
//         // Transfer to device and then do trasnspose since it's usually faster.
//         let tensor = self.data;
//         let data = tensor.copy_into_backend(backend).await?;
//         let data = data.transpose();
//         Ok(RsCodeWord::new(data))
//     }
// }
