//! GPU tracegen stubs for other precompile chips (Mprotect, Poseidon2).

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{MProtectChip, Poseidon2Chip};
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for MProtectChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("MProtectChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for Poseidon2Chip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Poseidon2Chip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{MProtectChip, Poseidon2Chip};
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_mprotect_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = MProtectChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_poseidon2_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Poseidon2Chip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
