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
use slop_alloc::Buffer;
use sp1_core_executor::events::ByteRecord;
use sp1_core_machine::air::{byte_lookups_from_histograms, WitProgram};
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};

use crate::{CudaTracegenAir, F};

/// Pack-and-launch the byte-lookup kernel for one chip, accumulating its byte/range
/// multiplicities into the SHARED shard histograms `range_dev`/`byte_dev`. Factored out
/// of every chip's `generate_device_dependencies` — the per-chip part is just recording
/// the op-DAG and packing inputs; the upload + launch are identical. The histograms are
/// allocated once per shard by the prover (see [`crate::new_byte_histograms`]) and read
/// back / reconstructed once, not per chip.
pub(crate) async fn accumulate_lookups(
    program: &WitProgram,
    inputs: &[u64],
    n_events: usize,
    range_dev: &mut DeviceBuffer<u32>,
    byte_dev: &mut DeviceBuffer<u32>,
    scope: &TaskScope,
) -> Result<(), CopyError> {
    if n_events == 0 {
        return Ok(());
    }
    let ops_c = program.to_c();
    let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
    ops_dev.extend_from_host_slice(&ops_c)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len(), scope.clone()).unwrap();
    in_dev.extend_from_host_slice(inputs)?;
    unsafe {
        const BLOCK: usize = 64;
        let grid = n_events.div_ceil(BLOCK);
        let args = args!(
            ops_dev.as_ptr(),
            ops_c.len(),
            program.num_inputs,
            in_dev.as_ptr(),
            n_events,
            range_dev.as_mut_ptr(),
            byte_dev.as_mut_ptr()
        );
        scope.launch_kernel(TaskScope::witgen_lookup_kernel(), grid, BLOCK, &args, 0).unwrap();
    }
    Ok(())
}

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

/// Runtime gate for the device-tracegen path.
///
/// The device-tracegen DSL (witgen → op-DAG → generic interpreter) was built and
/// validated for the full RISC-V ALU+memory+control ISA (iters 005–039), but the
/// e2e bench (iters 040–043) showed it **regresses ~17%** (correct but slower: the
/// per-chip-per-shard histogram readback + input-packing H2D + per-thread local-mem
/// traffic dwarf the modest column-gen win). So it is **off by default** — only
/// `Global` (the pre-existing baseline device chip) runs on device, matching the
/// baseline. Set `AR_DEVICE_CHIPS` to a comma-list to re-enable specific chips for
/// study (e.g. to re-bisect or profile); the code + tests are retained.
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
        None => name == "Global", // default: baseline behavior (only Global on device)
        Some(set) => set.contains(name),
    }
}

/// Whether the device byte-lookup dependency path is enabled (`AR_DEVICE_DEPS != 0`).
/// Lets the bench separate the device main-trace cost from the histogram-readback cost.
fn device_deps_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("AR_DEVICE_DEPS").map(|v| v != "0").unwrap_or(true))
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
        // `AR_DEVICE_DEPS=0` disables the device byte-lookup path globally (host
        // generates dependencies) to isolate the device main-trace cost from the
        // dense-histogram readback cost in the e2e bench.
        device_deps_enabled()
            && device_chip_name(self).is_some_and(|n| n != "Global" && device_chip_enabled(n))
    }

    async fn generate_device_dependencies(
        &self,
        input: &Self::Record,
        range_dev: &mut DeviceBuffer<u32>,
        byte_dev: &mut DeviceBuffer<u32>,
        scope: &TaskScope,
    ) -> Result<(), CopyError> {
        macro_rules! dispatch {
            ($chip:expr) => {
                $chip.generate_device_dependencies(input, range_dev, byte_dev, scope).await
            };
        }
        match self {
            Self::Add(chip) => dispatch!(chip),
            Self::Sub(chip) => dispatch!(chip),
            Self::Subw(chip) => dispatch!(chip),
            Self::Addw(chip) => dispatch!(chip),
            Self::Bitwise(chip) => dispatch!(chip),
            Self::Lt(chip) => dispatch!(chip),
            Self::Addi(chip) => dispatch!(chip),
            Self::ShiftLeft(chip) => dispatch!(chip),
            Self::ShiftRight(chip) => dispatch!(chip),
            Self::Mul(chip) => dispatch!(chip),
            Self::DivRem(chip) => dispatch!(chip),
            Self::AluX0(chip) => dispatch!(chip),
            Self::LoadDouble(chip) => dispatch!(chip),
            Self::LoadWord(chip) => dispatch!(chip),
            Self::LoadHalf(chip) => dispatch!(chip),
            Self::LoadByte(chip) => dispatch!(chip),
            Self::LoadX0(chip) => dispatch!(chip),
            Self::StoreDouble(chip) => dispatch!(chip),
            Self::StoreWord(chip) => dispatch!(chip),
            Self::StoreHalf(chip) => dispatch!(chip),
            Self::StoreByte(chip) => dispatch!(chip),
            Self::UType(chip) => dispatch!(chip),
            Self::Jal(chip) => dispatch!(chip),
            Self::Jalr(chip) => dispatch!(chip),
            Self::Branch(chip) => dispatch!(chip),
            _ => unimplemented!(),
        }
    }

    /// Reconstruct the `byte_lookups` map from the shared shard histograms (already read
    /// back to host) ONCE and merge it into `output`. Chip-independent: the dense
    /// histograms are opcode-indexed, so this single call yields the union of what the
    /// per-chip reconstructs used to produce. Mirrors the host `generate_dependencies`
    /// output that the Byte/Range chips consume.
    fn add_lookups_from_histograms(
        &self,
        range_hist: &[u32],
        byte_hist: &[u32],
        output: &mut Self::Record,
    ) {
        let map = byte_lookups_from_histograms(range_hist, byte_hist);
        output.add_byte_lookup_events_from_maps(vec![&map]);
    }
}
