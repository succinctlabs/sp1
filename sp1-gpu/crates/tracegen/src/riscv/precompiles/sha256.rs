//! GPU tracegen stubs for SHA-256 precompile chips.

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{
    ShaCompressChip, ShaCompressControlChip, ShaExtendChip, ShaExtendControlChip,
};
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for ShaExtendChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("ShaExtendChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for ShaExtendControlChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("ShaExtendControlChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for ShaCompressChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("ShaCompressChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for ShaCompressControlChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("ShaCompressControlChip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{
        ShaCompressChip, ShaCompressControlChip, ShaExtendChip, ShaExtendControlChip,
    };
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_sha_extend_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ShaExtendChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_sha_extend_control_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ShaExtendControlChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_sha_compress_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ShaCompressChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_sha_compress_control_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ShaCompressControlChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
