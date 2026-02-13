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
            Self::DivRem(chip) => chip.supports_device_main_tracegen(),
            Self::Lt(chip) => chip.supports_device_main_tracegen(),
            Self::Bitwise(chip) => chip.supports_device_main_tracegen(),
            Self::ShiftLeft(chip) => chip.supports_device_main_tracegen(),
            Self::ShiftRight(chip) => chip.supports_device_main_tracegen(),
            Self::LoadByte(chip) => chip.supports_device_main_tracegen(),
            Self::LoadHalf(chip) => chip.supports_device_main_tracegen(),
            Self::LoadWord(chip) => chip.supports_device_main_tracegen(),
            Self::LoadDouble(chip) => chip.supports_device_main_tracegen(),
            Self::LoadX0(chip) => chip.supports_device_main_tracegen(),
            Self::StoreByte(chip) => chip.supports_device_main_tracegen(),
            Self::StoreHalf(chip) => chip.supports_device_main_tracegen(),
            Self::StoreWord(chip) => chip.supports_device_main_tracegen(),
            Self::StoreDouble(chip) => chip.supports_device_main_tracegen(),
            Self::UType(chip) => chip.supports_device_main_tracegen(),
            Self::Branch(chip) => chip.supports_device_main_tracegen(),
            Self::Jal(chip) => chip.supports_device_main_tracegen(),
            Self::Jalr(chip) => chip.supports_device_main_tracegen(),
            // Self::SyscallInstrs(chip) => chip.supports_device_main_tracegen(),
            // Self::SyscallCore(chip) => chip.supports_device_main_tracegen(),
            // Self::SyscallPrecompile(chip) => chip.supports_device_main_tracegen(),
            // Self::ByteLookup(chip) => chip.supports_device_main_tracegen(),
            // Self::RangeLookup(chip) => chip.supports_device_main_tracegen(),
            Self::MemoryGlobalInit(chip) => chip.supports_device_main_tracegen(),
            Self::MemoryGlobalFinal(chip) => chip.supports_device_main_tracegen(),
            Self::MemoryLocal(chip) => chip.supports_device_main_tracegen(),
            Self::MemoryBump(chip) => chip.supports_device_main_tracegen(),
            Self::StateBump(chip) => chip.supports_device_main_tracegen(),
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
            Self::DivRem(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Lt(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Bitwise(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::ShiftLeft(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::ShiftRight(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadByte(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadHalf(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadWord(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadDouble(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::LoadX0(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreByte(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreHalf(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreWord(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StoreDouble(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::UType(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Branch(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Jal(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Jalr(chip) => chip.generate_trace_device(input, output, scope).await,
            // Self::SyscallInstrs(chip) => chip.generate_trace_device(input, output, scope).await,
            // Self::SyscallCore(chip) => chip.generate_trace_device(input, output, scope).await,
            // Self::SyscallPrecompile(chip) => chip.generate_trace_device(input, output, scope).await,
            // Self::ByteLookup(chip) => chip.generate_trace_device(input, output, scope).await,
            // Self::RangeLookup(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryGlobalInit(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryGlobalFinal(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryLocal(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryBump(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::StateBump(chip) => chip.generate_trace_device(input, output, scope).await,
            _ => unimplemented!(),
        }
    }
}
