//! GPU tracegen stubs for Keccak precompile chips.

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{KeccakPermuteChip, KeccakPermuteControlChip};
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for KeccakPermuteChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("KeccakPermuteChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for KeccakPermuteControlChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("KeccakPermuteControlChip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{KeccakPermuteChip, KeccakPermuteControlChip};
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_keccak_permute_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = KeccakPermuteChip::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_keccak_permute_control_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = KeccakPermuteControlChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
