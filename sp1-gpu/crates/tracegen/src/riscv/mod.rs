mod add;
mod addi;
mod alu_x0;
mod addw;
mod bitwise;
mod branch;
mod divrem;
mod global;
mod jal;
mod jalr;
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
pub(crate) const WITGEN_MAX_WIRES: usize = 256;

use slop_alloc::mem::CopyError;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{DeviceMle, TaskScope};

use crate::{CudaTracegenAir, F};

/// Name of the device-capable chip variant (`None` for chips without a device
/// tracegen impl, and for `Mul`/`DivRem` which are gated to host — too wide for the
/// 256-wire kernel). Used by the `AR_DEVICE_CHIPS` runtime gate.
fn device_chip_name(air: &RiscvAir<F>) -> Option<&'static str> {
    Some(match air {
        RiscvAir::Global(_) => "Global",
        RiscvAir::Add(_) => "Add",
        RiscvAir::Sub(_) => "Sub",
        RiscvAir::Subw(_) => "Subw",
        RiscvAir::Addw(_) => "Addw",
        RiscvAir::Bitwise(_) => "Bitwise",
        RiscvAir::Lt(_) => "Lt",
        RiscvAir::Addi(_) => "Addi",
        RiscvAir::ShiftLeft(_) => "ShiftLeft",
        RiscvAir::ShiftRight(_) => "ShiftRight",
        RiscvAir::AluX0(_) => "AluX0",
        RiscvAir::LoadDouble(_) => "LoadDouble",
        RiscvAir::LoadWord(_) => "LoadWord",
        RiscvAir::LoadHalf(_) => "LoadHalf",
        RiscvAir::LoadByte(_) => "LoadByte",
        RiscvAir::LoadX0(_) => "LoadX0",
        RiscvAir::StoreDouble(_) => "StoreDouble",
        RiscvAir::StoreWord(_) => "StoreWord",
        RiscvAir::StoreHalf(_) => "StoreHalf",
        RiscvAir::StoreByte(_) => "StoreByte",
        RiscvAir::UType(_) => "UType",
        RiscvAir::Jal(_) => "Jal",
        RiscvAir::Jalr(_) => "Jalr",
        RiscvAir::Branch(_) => "Branch",
        _ => return None,
    })
}

/// Runtime gate for bisecting device-tracegen correctness. If `AR_DEVICE_CHIPS` is
/// unset, every device-capable chip uses the device path (production behavior). If
/// set to a comma-list of chip names, only those use the device path (the rest fall
/// back to host) — letting us isolate a buggy chip by restarting the server, no
/// recompile. Set it to e.g. `none` to force the all-host baseline.
fn device_chip_enabled(name: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::OnceLock;
    static FILTER: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    let filter = FILTER.get_or_init(|| {
        std::env::var("AR_DEVICE_CHIPS").ok().map(|v| {
            v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        })
    });
    match filter {
        None => true,
        Some(set) => set.contains(name),
    }
}

impl CudaTracegenAir<F> for RiscvAir<F> {
    fn supports_device_main_tracegen(&self) -> bool {
        device_chip_name(self).is_some_and(device_chip_enabled)
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
            Self::Jal(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Jalr(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Branch(chip) => chip.generate_trace_device(input, output, scope).await,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }

    fn supports_device_dependencies(&self) -> bool {
        // Same gate as main tracegen, but `Global` has no device dependency path.
        device_chip_name(self).is_some_and(|n| n != "Global" && device_chip_enabled(n))
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
            Self::Jal(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Jalr(chip) => chip.generate_device_dependencies(input, output, scope).await,
            Self::Branch(chip) => chip.generate_device_dependencies(input, output, scope).await,
            _ => unimplemented!(),
        }
    }
}
