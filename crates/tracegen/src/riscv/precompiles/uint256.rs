//! GPU tracegen stubs for Uint256 precompile chips.

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{U256x2048MulChip, Uint256MulChip};
use sp1_core_machine::syscall::precompiles::uint256_ops::Uint256OpsChip;
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for Uint256MulChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Uint256MulChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for Uint256OpsChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Uint256OpsChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for U256x2048MulChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("U256x2048MulChip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{U256x2048MulChip, Uint256MulChip};
    use sp1_core_machine::syscall::precompiles::uint256_ops::Uint256OpsChip;
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_uint256_mul_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Uint256MulChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_uint256_ops_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Uint256OpsChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_u256x2048_mul_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = U256x2048MulChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
