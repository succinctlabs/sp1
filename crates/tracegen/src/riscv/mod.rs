mod alu;
mod bitwise;
mod control_flow;
mod global;
mod lookup;
mod memory_load;
mod memory_state;
mod memory_store;
mod precompiles;
mod program;
mod shift;
mod syscall;

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for RiscvAir<F> {
    fn supports_device_preprocessed_tracegen(&self) -> bool {
        match self {
            Self::Program(chip) => chip.supports_device_preprocessed_tracegen(),
            _ => false,
        }
    }

    async fn generate_preprocessed_trace_device(
        &self,
        program: &<Self as MachineAir<F>>::Program,
        scope: &TaskScope,
    ) -> Result<Option<DeviceMle<F>>, CopyError> {
        match self {
            Self::Program(chip) => chip.generate_preprocessed_trace_device(program, scope).await,
            _ => unimplemented!(),
        }
    }

    fn supports_device_main_tracegen(&self) -> bool {
        match self {
            Self::Global(chip) => chip.supports_device_main_tracegen(),
            Self::Program(chip) => chip.supports_device_main_tracegen(),
            Self::Add(chip) => chip.supports_device_main_tracegen(),
            Self::Addw(chip) => chip.supports_device_main_tracegen(),
            Self::Addi(chip) => chip.supports_device_main_tracegen(),
            Self::Sub(chip) => chip.supports_device_main_tracegen(),
            Self::Subw(chip) => chip.supports_device_main_tracegen(),
            Self::Mul(chip) => chip.supports_device_main_tracegen(),
            // DivRem GPU tracegen is implemented but has bugs - disabled for now
            // Self::DivRem(chip) => chip.supports_device_main_tracegen(),
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => false,
        }
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        match self {
            Self::Global(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Program(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Add(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Addw(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Addi(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Sub(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Subw(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Mul(chip) => chip.generate_trace_device(input, output, scope).await,
            // DivRem GPU tracegen is implemented but has bugs - disabled for now
            // Self::DivRem(chip) => chip.generate_trace_device(input, output, scope).await,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }
}
