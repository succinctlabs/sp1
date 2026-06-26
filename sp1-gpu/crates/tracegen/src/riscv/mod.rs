mod add;
mod addi;
mod addw;
mod bitwise;
mod global;
mod lt;
mod sub;
mod subw;

/// Per-thread wire-array capacity in the witgen interpreter kernel
/// (`WITGEN_MAX_WIRES` in `witgen_interp.cu`). A recorded gadget whose
/// [`num_wires`](sp1_core_machine::air::WitProgram::num_wires) exceeds this would
/// overflow the kernel's per-thread arrays, so device tracegen asserts against it.
pub(crate) const WITGEN_MAX_WIRES: usize = 256;

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for RiscvAir<F> {
    fn supports_device_main_tracegen(&self) -> bool {
        match self {
            Self::Global(chip) => chip.supports_device_main_tracegen(),
            Self::Add(chip) => chip.supports_device_main_tracegen(),
            Self::Sub(chip) => chip.supports_device_main_tracegen(),
            Self::Subw(chip) => chip.supports_device_main_tracegen(),
            Self::Addw(chip) => chip.supports_device_main_tracegen(),
            Self::Bitwise(chip) => chip.supports_device_main_tracegen(),
            Self::Lt(chip) => chip.supports_device_main_tracegen(),
            Self::Addi(chip) => chip.supports_device_main_tracegen(),
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
            Self::Add(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Sub(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Subw(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Addw(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Bitwise(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Lt(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Addi(chip) => chip.generate_trace_device(input, output, scope).await,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }

    fn supports_device_dependencies(&self) -> bool {
        match self {
            Self::Add(chip) => chip.supports_device_dependencies(),
            Self::Sub(chip) => chip.supports_device_dependencies(),
            Self::Subw(chip) => chip.supports_device_dependencies(),
            Self::Addw(chip) => chip.supports_device_dependencies(),
            Self::Bitwise(chip) => chip.supports_device_dependencies(),
            Self::Lt(chip) => chip.supports_device_dependencies(),
            Self::Addi(chip) => chip.supports_device_dependencies(),
            _ => false,
        }
    }

    async fn generate_device_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<(), CopyError> {
        match self {
            Self::Add(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Sub(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Subw(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Addw(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Bitwise(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Lt(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Addi(chip) => chip.generate_device_dependencies(input, output, scope).await,
            _ => unimplemented!(),
        }
    }
}
