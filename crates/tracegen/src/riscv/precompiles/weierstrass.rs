//! GPU tracegen stubs for Weierstrass curve precompile chips (secp256k1, secp256r1).

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{
    Secp256k1Parameters, Secp256r1Parameters, SwCurve, WeierstrassAddAssignChip,
    WeierstrassDecompressChip, WeierstrassDoubleAssignChip,
};
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

// Secp256k1 chips

impl CudaTracegenAir<F> for WeierstrassDecompressChip<SwCurve<Secp256k1Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDecompressChip<Secp256k1> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassAddAssignChip<Secp256k1> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDoubleAssignChip<Secp256k1> GPU tracegen not yet implemented")
    }
}

// Secp256r1 chips

impl CudaTracegenAir<F> for WeierstrassDecompressChip<SwCurve<Secp256r1Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDecompressChip<Secp256r1> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassAddAssignChip<SwCurve<Secp256r1Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassAddAssignChip<Secp256r1> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassDoubleAssignChip<SwCurve<Secp256r1Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDoubleAssignChip<Secp256r1> GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{
        Secp256k1Parameters, Secp256r1Parameters, SwCurve, WeierstrassAddAssignChip,
        WeierstrassDecompressChip, WeierstrassDoubleAssignChip,
    };
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_k256_decompress_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassDecompressChip::<SwCurve<Secp256k1Parameters>>::with_lsb_rule();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_secp256k1_add_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassAddAssignChip::<SwCurve<Secp256k1Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_secp256k1_double_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassDoubleAssignChip::<SwCurve<Secp256k1Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_p256_decompress_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassDecompressChip::<SwCurve<Secp256r1Parameters>>::with_lsb_rule();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_secp256r1_add_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassAddAssignChip::<SwCurve<Secp256r1Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_secp256r1_double_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassDoubleAssignChip::<SwCurve<Secp256r1Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
