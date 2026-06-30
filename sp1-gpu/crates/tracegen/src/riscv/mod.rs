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
use slop_tensor::Tensor;
use sp1_core_executor::events::ByteRecord;
use sp1_core_machine::air::{byte_lookups_from_histograms, WitProgram};
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};

use crate::{CudaTracegenAir, F};

/// Raw device pointers to the shard's shared byte/range histograms, shareable across
/// the concurrently-launched device-tracegen futures (each fused kernel `atomicAdd`s
/// into them — safe under concurrency). The buffers are owned by the trace phase and
/// outlive the launches; the histogram is read back only after the device stream
/// drains. `Send`/`Sync` because the only access is enqueuing kernel launches that
/// take the pointers by value (the device-side atomics serialize the writes).
#[derive(Clone, Copy)]
pub struct LookupHist {
    pub range: *mut u32,
    pub byte: *mut u32,
}
// SAFETY: see the type doc — the pointers are only handed to kernel launches, whose
// histogram writes are atomic; no host-side aliasing of the pointee occurs until the
// stream is drained and the owner reads it back.
unsafe impl Send for LookupHist {}
unsafe impl Sync for LookupHist {}

/// Run the FUSED witgen kernel for one chip: a single op-DAG pass that both writes the
/// gadget's trace columns (returned) AND accumulates its byte/range lookups into the
/// shared shard histograms `hist`. This is the union of [`accumulate_lookups`] (lookup
/// kernel) and the per-chip `generate_trace_device` (column kernel) — running the
/// witgen ONCE instead of twice over the same inputs, so there is no separate device
/// dependency pre-pass and no duplicate input upload.
pub(crate) async fn generate_trace_and_lookups(
    program: &WitProgram,
    col_wires: &[u32],
    n_cols: usize,
    inputs: &[u64],
    n_events: usize,
    height: usize,
    hist: LookupHist,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    // Zeroed trace; only event rows are written (padding rows stay 0 — is_real=0).
    let trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
    generate_trace_and_lookups_into(program, col_wires, inputs, n_events, height, trace, hist, scope)
        .await
}

/// Like [`generate_trace_and_lookups`] but writes into a caller-provided `trace` that
/// is already initialized — for chips whose padding rows are NOT all-zero (e.g.
/// ShiftLeft/ShiftRight broadcast a non-zero column template across padding rows before
/// the kernel overwrites the event rows). Uploads the op-DAG + column map + inputs and
/// launches the fused column+lookup kernel into `trace`.
pub(crate) async fn generate_trace_and_lookups_into(
    program: &WitProgram,
    col_wires: &[u32],
    inputs: &[u64],
    n_events: usize,
    height: usize,
    mut trace: Tensor<F, TaskScope>,
    hist: LookupHist,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    let n_cols = col_wires.len();
    let ops_c = program.to_c();
    let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
    ops_dev.extend_from_host_slice(&ops_c)?;
    let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
    col_dev.extend_from_host_slice(col_wires)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
    in_dev.extend_from_host_slice(inputs)?;

    if n_events > 0 {
        unsafe {
            const BLOCK: usize = 64;
            let grid = n_events.div_ceil(BLOCK);
            let args = args!(
                trace.as_mut_ptr(),
                height,
                ops_dev.as_ptr(),
                ops_c.len(),
                col_dev.as_ptr(),
                n_cols,
                program.num_inputs,
                in_dev.as_ptr(),
                n_events,
                hist.range,
                hist.byte
            );
            scope.launch_kernel(TaskScope::witgen_fused_kernel(), grid, BLOCK, &args, 0).unwrap();
        }
    }

    Ok(DeviceMle::from(trace))
}

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

    fn pack_device_lookup_inputs(&self, input: &Self::Record) -> Vec<u64> {
        let height =
            <Self as sp1_hypercube::air::MachineAir<F>>::num_rows(self, input).unwrap_or(0);
        macro_rules! pk {
            ($events:expr, $packfn:path) => {{
                let n = if height == 0 { 0 } else { $events.len() };
                $packfn(&$events[..n])
            }};
        }
        match self {
            Self::Add(_) => pk!(input.add_events, add::pack_add_inputs),
            Self::Sub(_) => pk!(input.sub_events, sub::pack_sub_inputs),
            Self::Subw(_) => pk!(input.subw_events, subw::pack_subw_inputs),
            Self::Addw(_) => pk!(input.addw_events, addw::pack_addw_inputs),
            Self::Bitwise(_) => pk!(input.bitwise_events, bitwise::pack_bitwise_inputs),
            Self::Lt(_) => pk!(input.lt_events, lt::pack_lt_inputs),
            Self::Addi(_) => pk!(input.addi_events, addi::pack_addi_inputs),
            Self::ShiftLeft(_) => pk!(input.shift_left_events, sll::pack_sll_inputs),
            Self::ShiftRight(_) => pk!(input.shift_right_events, sr::pack_sr_inputs),
            Self::AluX0(_) => pk!(input.alu_x0_events, alu_x0::pack_alu_x0_inputs),
            Self::LoadDouble(_) => {
                pk!(input.memory_load_double_events, load_double::pack_ld_inputs)
            }
            Self::LoadWord(_) => pk!(input.memory_load_word_events, load_word::pack_lw_inputs),
            Self::LoadHalf(_) => {
                pk!(input.memory_load_half_events, load_half::pack_load_half_inputs)
            }
            Self::LoadByte(_) => {
                pk!(input.memory_load_byte_events, load_byte::pack_load_byte_inputs)
            }
            Self::LoadX0(_) => pk!(input.memory_load_x0_events, load_x0::pack_lx0_inputs),
            Self::StoreDouble(_) => {
                pk!(input.memory_store_double_events, store_double::pack_store_double_inputs)
            }
            Self::StoreWord(_) => {
                pk!(input.memory_store_word_events, store_word::pack_store_word_inputs)
            }
            Self::StoreHalf(_) => {
                pk!(input.memory_store_half_events, store_half::pack_store_half_inputs)
            }
            Self::StoreByte(_) => {
                pk!(input.memory_store_byte_events, store_byte::pack_store_byte_inputs)
            }
            Self::UType(_) => pk!(input.utype_events, utype::pack_utype_inputs),
            Self::Jal(_) => pk!(input.jal_events, jal::pack_jal_inputs),
            Self::Jalr(_) => pk!(input.jalr_events, jalr::pack_jalr_inputs),
            Self::Branch(_) => pk!(input.branch_events, branch::pack_branch_inputs),
            _ => Vec::new(),
        }
    }

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        macro_rules! dispatch {
            ($chip:expr) => {
                $chip.generate_trace_device_with_lookups(input, inputs, hist, scope).await
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

    /// Build a (minimal) record carrying the FULL `byte_lookups` map — the host chips'
    /// lookups already in `base` (from the host `generate_dependencies`) unioned with the
    /// device chips' lookups reconstructed from the shared histograms — so the deferred
    /// Byte/Range table chips can generate their traces from it. Replaces the old
    /// `merge_device_dependencies` pre-pass: the device lookups now come from the fused
    /// main-trace kernels, so this runs once after device tracegen completes.
    fn record_with_byte_lookups(
        &self,
        base: &Self::Record,
        range_hist: &[u32],
        byte_hist: &[u32],
    ) -> Self::Record {
        let dev_map = byte_lookups_from_histograms(range_hist, byte_hist);
        let mut rec = Self::Record::default();
        rec.add_byte_lookup_events_from_maps(vec![&base.byte_lookups, &dev_map]);
        rec
    }

    fn host_lookup_scatter(
        &self,
        record: &Self::Record,
    ) -> (Vec<u64>, Vec<u32>, Vec<u64>, Vec<u32>) {
        use sp1_core_executor::ByteOpcode;
        use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
        let n = record.byte_lookups.len();
        let (mut range_idx, mut range_mult) = (Vec::with_capacity(n), Vec::with_capacity(n));
        let (mut byte_idx, mut byte_mult) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for (lookup, &mult) in record.byte_lookups.iter() {
            // Mirror range/trace.rs and bytes/trace.rs `generate_trace_into` index math
            // (and the inverse in `byte_lookups_from_histograms`), so the scattered host
            // multiplicities land in the same cells the device chips' atomics did.
            if lookup.opcode == ByteOpcode::Range {
                let idx = lookup.a as usize + (1usize << lookup.b);
                range_idx.push(idx as u64);
                range_mult.push(mult as u32);
            } else {
                let row = ((lookup.b as usize) << 8) + lookup.c as usize;
                let idx = row * NUM_BYTE_MULT_COLS + lookup.opcode as usize;
                byte_idx.push(idx as u64);
                byte_mult.push(mult as u32);
            }
        }
        (range_idx, range_mult, byte_idx, byte_mult)
    }
}
