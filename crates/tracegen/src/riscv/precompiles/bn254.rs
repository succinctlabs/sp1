//! GPU tracegen stubs for BN254 precompile chips.

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::{
    Bn254Parameters, SwCurve, WeierstrassAddAssignChip, WeierstrassDoubleAssignChip,
};
use sp1_core_machine::syscall::precompiles::fptower::{
    Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip,
};
use sp1_curves::weierstrass::bn254::Bn254BaseField;
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for WeierstrassAddAssignChip<SwCurve<Bn254Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassAddAssignChip<Bn254> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("WeierstrassDoubleAssignChip<Bn254> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for FpOpChip<Bn254BaseField> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("FpOpChip<Bn254> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for Fp2MulAssignChip<Bn254BaseField> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Fp2MulAssignChip<Bn254> GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for Fp2AddSubAssignChip<Bn254BaseField> {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("Fp2AddSubAssignChip<Bn254> GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::ExecutionRecord;
    use sp1_core_machine::riscv::{
        Bn254Parameters, SwCurve, WeierstrassAddAssignChip, WeierstrassDoubleAssignChip,
    };
    use sp1_core_machine::syscall::precompiles::fptower::{
        Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip,
    };
    use sp1_curves::weierstrass::bn254::Bn254BaseField;
    use sp1_gpu_cudart::TaskScope;

    use crate::CudaTracegenAir;

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bn254_add_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bn254_double_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = WeierstrassDoubleAssignChip::<SwCurve<Bn254Parameters>>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bn254_fp_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = FpOpChip::<Bn254BaseField>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bn254_fp2_mul_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Fp2MulAssignChip::<Bn254BaseField>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_bn254_fp2_add_sub_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = Fp2AddSubAssignChip::<Bn254BaseField>::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
