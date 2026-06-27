mod add;
mod addi;
mod alu_x0;
mod addw;
mod bitwise;
mod divrem;
mod global;
mod load_byte;
mod load_double;
mod load_half;
mod load_word;
mod load_x0;
mod lt;
mod mul;
mod sll;
mod sr;
mod store_byte;
mod store_double;
mod store_half;
mod store_word;
mod sub;
mod subw;
mod utype;

/// Per-thread wire-array capacity in the witgen interpreter kernel
/// (`WITGEN_MAX_WIRES` in `witgen_interp.cu`). A recorded gadget whose
/// [`num_wires`](sp1_core_machine::air::WitProgram::num_wires) exceeds this would
/// overflow the kernel's per-thread arrays, so device tracegen asserts against it.
pub(crate) const WITGEN_MAX_WIRES: usize = 1536;

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
            Self::ShiftLeft(chip) => chip.supports_device_main_tracegen(),
            Self::ShiftRight(chip) => chip.supports_device_main_tracegen(),
            Self::Mul(chip) => chip.supports_device_main_tracegen(),
            Self::DivRem(chip) => chip.supports_device_main_tracegen(),
            Self::AluX0(chip) => chip.supports_device_main_tracegen(),
            Self::LoadDouble(chip) => chip.supports_device_main_tracegen(),
            Self::LoadWord(chip) => chip.supports_device_main_tracegen(),
            Self::LoadHalf(chip) => chip.supports_device_main_tracegen(),
            Self::LoadByte(chip) => chip.supports_device_main_tracegen(),
            Self::LoadX0(chip) => chip.supports_device_main_tracegen(),
            Self::StoreDouble(chip) => chip.supports_device_main_tracegen(),
            Self::StoreWord(chip) => chip.supports_device_main_tracegen(),
            Self::StoreHalf(chip) => chip.supports_device_main_tracegen(),
            Self::StoreByte(chip) => chip.supports_device_main_tracegen(),
            Self::UType(chip) => chip.supports_device_main_tracegen(),
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
            Self::ShiftLeft(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::ShiftRight(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Mul(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::DivRem(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::AluX0(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadDouble(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadWord(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadHalf(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadByte(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadX0(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreDouble(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreWord(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreHalf(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreByte(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::UType(chip) => chip.generate_trace_device(input, output, scope).await,
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
            Self::ShiftLeft(chip) => chip.supports_device_dependencies(),
            Self::ShiftRight(chip) => chip.supports_device_dependencies(),
            Self::Mul(chip) => chip.supports_device_dependencies(),
            Self::DivRem(chip) => chip.supports_device_dependencies(),
            Self::AluX0(chip) => chip.supports_device_dependencies(),
            Self::LoadDouble(chip) => chip.supports_device_dependencies(),
            Self::LoadWord(chip) => chip.supports_device_dependencies(),
            Self::LoadHalf(chip) => chip.supports_device_dependencies(),
            Self::LoadByte(chip) => chip.supports_device_dependencies(),
            Self::LoadX0(chip) => chip.supports_device_dependencies(),
            Self::StoreDouble(chip) => chip.supports_device_dependencies(),
            Self::StoreWord(chip) => chip.supports_device_dependencies(),
            Self::StoreHalf(chip) => chip.supports_device_dependencies(),
            Self::StoreByte(chip) => chip.supports_device_dependencies(),
            Self::UType(chip) => chip.supports_device_dependencies(),
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
            Self::ShiftLeft(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::ShiftRight(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Mul(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::DivRem(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::AluX0(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::LoadDouble(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::LoadWord(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::LoadHalf(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::LoadByte(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::LoadX0(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::StoreDouble(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::StoreWord(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::StoreHalf(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::StoreByte(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::UType(chip) => chip.generate_device_dependencies(input, output, scope).await,
            _ => unimplemented!(),
        }
    }
}
