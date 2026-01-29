//! GPU tracegen stubs for BLS12-381 precompile chips.

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{
    Bls12381Parameters, SwCurve, WeierstrassAddAssignChip, WeierstrassDecompressChip,
    WeierstrassDoubleAssignChip,
};
use sp1_core_machine::syscall::precompiles::fptower::{
    Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip,
};
use sp1_curves::weierstrass::bls12_381::Bls12381BaseField;
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassAddAssignChip<Bls12381> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDoubleAssignChip<Bls12381> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassDecompressChip<SwCurve<Bls12381Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDecompressChip<Bls12381> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for FpOpChip<Bls12381BaseField> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("FpOpChip<Bls12381> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for Fp2MulAssignChip<Bls12381BaseField> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Fp2MulAssignChip<Bls12381> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for Fp2AddSubAssignChip<Bls12381BaseField> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Fp2AddSubAssignChip<Bls12381> GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{
        Bls12381Parameters, SwCurve, WeierstrassAddAssignChip, WeierstrassDecompressChip,
        WeierstrassDoubleAssignChip,
    };
    use sp1_core_machine::syscall::precompiles::fptower::{
        Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip,
    };
    use sp1_curves::weierstrass::bls12_381::Bls12381BaseField;
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bls12381_add_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassAddAssignChip::<SwCurve<Bls12381Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bls12381_double_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassDoubleAssignChip::<SwCurve<Bls12381Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bls12381_decompress_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip =
                WeierstrassDecompressChip::<SwCurve<Bls12381Parameters>>::with_lexicographic_rule();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bls12381_fp_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = FpOpChip::<Bls12381BaseField>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bls12381_fp2_mul_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Fp2MulAssignChip::<Bls12381BaseField>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bls12381_fp2_add_sub_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Fp2AddSubAssignChip::<Bls12381BaseField>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
