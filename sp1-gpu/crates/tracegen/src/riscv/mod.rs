//! Device tracegen for the RISC-V chips via the witgen IR (see
//! `crates/core/machine/src/air/WITGEN-IR.md` and the module doc of
//! `crates/core/machine/src/air/witness_record.rs` for the IR itself).
//!
//! Each chip submodule contributes the CPU side of a port: record the chip's
//! `witgen` op-DAG once, pack its events into flat per-row `u64` inputs, and
//! implement [`CudaTracegenAir`]. The generic upload-and-launch work is factored
//! into the launcher family in THIS file:
//!
//! - **Production path** (chips with `supports_device_dependencies`, i.e. all
//!   byte-lookup-only chips): the prover calls
//!   `generate_trace_device_with_lookups`, which lands in
//!   [`generate_trace_and_lookups`] / [`generate_trace_and_lookups_slots`] (or
//!   the `_into` variants for non-zero padding templates). By default these
//!   route to [`generate_trace_and_lookups_slots_into`], which tiers the fused
//!   kernel by the STREAMING footprint:
//!     1. `streaming_max <= WITGEN_SMEM_CAP` (24) → shared-memory streaming
//!        kernel;
//!     2. `streaming_max <= WITGEN_MAX_WIRES` (256) → local-memory streaming
//!        kernel;
//!     3. otherwise (or a non-empty multi-column epilogue) → pinned
//!        register-allocated fallback (`witgen_fused_slots_kernel`).
//!
//!   `AR_WITGEN_SLOTS=0` is the validated kill-switch back to the SSA fused
//!   kernel.
//! - **Non-fused column path**: the prover calls the per-chip
//!   `generate_trace_device` only for `Global` (no byte lookups) and for every
//!   fused chip when `AR_DEVICE_DEPS=0` (fused-ONLY chips — DivRem, Keccak* —
//!   instead fall back to host tracegen entirely, see
//!   `supports_device_main_tracegen`). Narrow chips launch the SSA
//!   `witgen_interp_kernel` directly; wide ones use
//!   [`generate_columns_slots_into`]. Chips that also emit
//!   `GlobalInteractionEvent`s (MemoryLocal / MemoryGlobal* / Syscall*) fuse
//!   their byte lookups like everyone else; the globals come from the host
//!   `generate_global_dependencies` pass.
//! - **Standalone lookup path** ([`accumulate_lookups`] /
//!   [`accumulate_lookups_slots`], via the per-chip
//!   `generate_device_dependencies`): superseded in production by the fused
//!   kernels; retained as the reference/validation path (see the docs on those
//!   functions).
//!
//! Porting a chip requires FOUR dispatch arms here (`device_chip_name`,
//! `pack_device_lookup_inputs`, `generate_trace_device_with_lookups`,
//! `generate_device_dependencies`) — a missing arm is a prove-time
//! `unimplemented!()` or an empty trace (the iter-067 trap).

mod add;
mod addi;
mod addw;
mod alu_x0;
mod bitwise;
mod branch;
mod divrem;
mod global;
mod jal;
mod jalr;
mod keccak;
mod keccak_control;
mod load_byte;
mod load_double;
mod load_half;
mod load_word;
mod load_x0;
mod lt;
mod memory_bump;
mod memory_global;
mod memory_local;
mod mul;
mod sha_compress;
mod sha_compress_control;
mod sha_extend;
mod sha_extend_control;
mod sll;
mod sr;
mod state_bump;
mod store_byte;
mod store_double;
mod store_half;
mod store_word;
mod sub;
mod subw;
mod syscall;
mod syscall_instrs;
mod utype;

// The lookup kernels hard-code the byte-table shape as `WITGEN_NUM_BYTE_MULT_COLS`
// (= 6) and `WITGEN_BYTE_U8RANGE_COL` (= 3) in `witgen_interp.cu`; fail the build
// here if the Rust-side constants they mirror ever drift.
const _: () = {
    assert!(sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS == 6);
    assert!(sp1_core_executor::ByteOpcode::U8Range as usize == 3);
};

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
// The kernel sizing constants are defined next to the IR (single source of truth,
// exported to `witgen_interp.cu` through cbindgen — the kernels' static array
// sizes and this crate's launcher asserts/tiering can no longer drift apart).
use sp1_core_machine::air::{
    StreamingLowering, WitOpC, WitOpCSlot, WitProgram, WITGEN_MAX_WIRES, WITGEN_SMEM_BLOCK,
    WITGEN_SMEM_CAP,
};
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

/// The per-CHIP half of a witgen launch: the recorded op-DAG, its column map, and
/// its device lowerings. Chips build one of these ONCE per process (in a
/// per-chip `OnceLock` — see e.g. `add::add_witgen_chip`) instead of re-recording
/// and re-lowering the same program on every shard: the program is
/// shard-independent by construction (one symbolic execution covers every row).
///
/// The streaming lowering (the production tier selector) is computed eagerly; the
/// pinned and SSA forms lazily — fused-only wide chips (Keccak: 2641-slot pinned
/// floor) never touch the pinned form, and the SSA form only runs under the
/// `AR_WITGEN_SLOTS=0` kill-switch or the standalone-lookup reference path.
pub(crate) struct WitgenChip {
    pub program: WitProgram,
    pub col_wires: Vec<u32>,
    /// Streaming (store-through) lowering — the production default tier.
    pub streaming: StreamingLowering,
    pinned: std::sync::OnceLock<PinnedLowering>,
    ssa: std::sync::OnceLock<Vec<WitOpC>>,
}

/// The pinned (register-allocated, columns-live-to-the-end) lowering of a chip —
/// the fallback tier and the non-fused slot kernels' form.
pub(crate) struct PinnedLowering {
    pub ops: Vec<WitOpCSlot>,
    pub max_slots: u32,
    pub input_slots: Vec<u32>,
    pub col_slots: Vec<u32>,
}

impl WitgenChip {
    pub fn new(program: WitProgram, col_wires: Vec<u32>) -> Self {
        let streaming = program.lower_streaming(&col_wires);
        Self {
            program,
            col_wires,
            streaming,
            pinned: std::sync::OnceLock::new(),
            ssa: std::sync::OnceLock::new(),
        }
    }

    pub fn n_cols(&self) -> usize {
        self.col_wires.len()
    }

    /// The pinned lowering (computed on first use; panics if the chip's pinned
    /// footprint exceeds the kernel capacity — such chips are streaming-only).
    pub fn pinned(&self) -> &PinnedLowering {
        self.pinned.get_or_init(|| {
            let (slot, max_slots) = self.program.allocate_slots(&self.col_wires);
            assert!(
                max_slots as usize <= WITGEN_MAX_WIRES,
                "reg-alloc: {max_slots} live slots > kernel capacity {WITGEN_MAX_WIRES}"
            );
            let ni = self.program.num_inputs as usize;
            PinnedLowering {
                ops: self.program.to_c_slots(&slot),
                max_slots,
                input_slots: slot[..ni].to_vec(),
                col_slots: self.col_wires.iter().map(|&w| slot[w as usize]).collect(),
            }
        })
    }

    /// The flat SSA form (kill-switch + standalone-lookup reference path).
    pub fn ssa(&self) -> &[WitOpC] {
        self.ssa.get_or_init(|| self.program.to_c())
    }
}

/// The per-SHARD half of a witgen launch: one chip's packed event rows and the
/// padded trace height. Pairs with a [`WitgenChip`] at every launcher call site.
#[derive(Clone, Copy)]
pub(crate) struct WitgenBatch<'a> {
    /// Row-major packed inputs, `[n_events][chip.program.num_inputs]`.
    pub inputs: &'a [u64],
    /// Number of event (kernel) rows.
    pub n_events: usize,
    /// Padded trace height (rows the trace tensor is allocated for).
    pub height: usize,
}

/// Run the FUSED witgen kernel for one chip: a single op-DAG pass that both writes the
/// gadget's trace columns (returned) AND accumulates its byte/range lookups into the
/// shared shard histograms `hist`. This is the union of [`accumulate_lookups`] (lookup
/// kernel) and the per-chip `generate_trace_device` (column kernel) — running the
/// witgen ONCE instead of twice over the same inputs, so there is no separate device
/// dependency pre-pass and no duplicate input upload.
///
/// PRODUCTION ENTRY POINT for most fused chips' `generate_trace_device_with_lookups`
/// (zero padding rows). By default it routes to the slot/streaming form (see
/// [`generate_trace_and_lookups_slots_into`] for the kernel tier ladder); the SSA
/// fused kernel below runs only under the `AR_WITGEN_SLOTS=0` kill-switch.
pub(crate) async fn generate_trace_and_lookups(
    chip: &WitgenChip,
    batch: WitgenBatch<'_>,
    hist: LookupHist,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    // Zeroed trace; only event rows are written (padding rows stay 0 — is_real=0).
    let trace = Tensor::<F, TaskScope>::zeros_in([chip.n_cols(), batch.height], scope.clone());
    generate_trace_and_lookups_into(chip, batch, trace, hist, scope).await
}

/// Whether the fused witgen path uses the register-allocated SLOT kernels (default)
/// or the legacy SSA ones (`AR_WITGEN_SLOTS=0` kill-switch). Slot form is wall-neutral
/// vs SSA (iter-072: fibonacci 12.51 vs 12.49s) but is the single consolidated form:
/// bounded footprint (wide gadgets fit) and the prerequisite for the shared-memory
/// tiers, so kernel work only targets one family.
pub(crate) fn witgen_slots_enabled() -> bool {
    static SLOTS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SLOTS.get_or_init(|| std::env::var("AR_WITGEN_SLOTS").map(|v| v != "0").unwrap_or(true))
}

/// Like [`generate_trace_and_lookups`] but writes into a caller-provided `trace` that
/// is already initialized — for chips whose padding rows are NOT all-zero (e.g.
/// ShiftLeft/ShiftRight broadcast a non-zero column template across padding rows before
/// the kernel overwrites the event rows). Uploads the op-DAG + column map + inputs and
/// launches the fused column+lookup kernel into `trace`.
pub(crate) async fn generate_trace_and_lookups_into(
    chip: &WitgenChip,
    batch: WitgenBatch<'_>,
    mut trace: Tensor<F, TaskScope>,
    hist: LookupHist,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    // Default path: the register-allocated slot form (see `witgen_slots_enabled`).
    if witgen_slots_enabled() {
        return generate_trace_and_lookups_slots_into(chip, batch, trace, hist, scope).await;
    }
    let WitgenBatch { inputs, n_events, height } = batch;
    let n_cols = chip.n_cols();
    let ops_c = chip.ssa();
    let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone())
        .expect("witgen: alloc device buffer for the op-DAG");
    ops_dev.extend_from_host_slice(ops_c)?;
    let mut col_dev = Buffer::try_with_capacity_in(chip.col_wires.len(), scope.clone())
        .expect("witgen: alloc device buffer for the column map");
    col_dev.extend_from_host_slice(&chip.col_wires)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone())
        .expect("witgen: alloc device buffer for the packed inputs");
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
                chip.program.num_inputs,
                in_dev.as_ptr(),
                n_events,
                hist.range,
                hist.byte
            );
            scope
                .launch_kernel(TaskScope::witgen_fused_kernel(), grid, BLOCK, &args, 0)
                .expect("witgen: launch fused SSA kernel");
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
///
/// CALLERS: the per-chip `generate_device_dependencies` impls (a path the prover no
/// longer takes — see the trait doc) and the fused-kernel unit tests, which use this
/// standalone lookup pass as the reference histogram (e.g.
/// `add::tests::test_add_fused_kernel`). Keep in sync with the lookup arms of the
/// fused kernels it validates.
pub(crate) async fn accumulate_lookups(
    chip: &WitgenChip,
    inputs: &[u64],
    n_events: usize,
    range_dev: &mut DeviceBuffer<u32>,
    byte_dev: &mut DeviceBuffer<u32>,
    scope: &TaskScope,
) -> Result<(), CopyError> {
    if n_events == 0 {
        return Ok(());
    }
    let ops_c = chip.ssa();
    let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone())
        .expect("witgen: alloc device buffer for the op-DAG");
    ops_dev.extend_from_host_slice(ops_c)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len(), scope.clone())
        .expect("witgen: alloc device buffer for the packed inputs");
    in_dev.extend_from_host_slice(inputs)?;
    unsafe {
        const BLOCK: usize = 64;
        let grid = n_events.div_ceil(BLOCK);
        let args = args!(
            ops_dev.as_ptr(),
            ops_c.len(),
            chip.program.num_inputs,
            in_dev.as_ptr(),
            n_events,
            range_dev.as_mut_ptr(),
            byte_dev.as_mut_ptr()
        );
        scope
            .launch_kernel(TaskScope::witgen_lookup_kernel(), grid, BLOCK, &args, 0)
            .expect("witgen: launch SSA lookup kernel");
    }
    Ok(())
}

/// Slot-indexed column tracegen for WIDE gadgets (Mul/DivRem, ultimately precompiles).
/// Register-allocates the op-DAG so the per-thread wire array is bounded by max-live
/// slots (Mul: 531 wires -> 100 slots) rather than one cell per op, then launches
/// `witgen_interp_slots_kernel`. Narrow chips keep the SSA `witgen_interp_kernel` path.
/// The `WITGEN_MAX_WIRES` assert now bounds SLOTS, not raw wires, so wide gadgets fit.
///
/// CALLERS: the wide chips' non-fused `generate_trace_device` impls (Mul, SHA family,
/// SyscallInstrs) — which the prover reaches only when the fused path is off
/// (`AR_DEVICE_DEPS=0`); otherwise exercised by the per-chip device tests.
pub(crate) async fn generate_columns_slots_into(
    chip: &WitgenChip,
    batch: WitgenBatch<'_>,
    mut trace: Tensor<F, TaskScope>,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    let WitgenBatch { inputs, n_events, height } = batch;
    let n_cols = chip.n_cols();
    let pinned = chip.pinned();
    tracing::debug!(
        target: "witgen_slots",
        max_slots = pinned.max_slots,
        streaming_max = chip.streaming.max_slots,
        epilogue = chip.streaming.epilogue.len(),
        n_cols,
        "witgen slot footprint"
    );

    let mut ops_dev = Buffer::try_with_capacity_in(pinned.ops.len(), scope.clone())
        .expect("witgen: alloc device buffer for the op-DAG");
    ops_dev.extend_from_host_slice(&pinned.ops)?;
    let mut col_dev = Buffer::try_with_capacity_in(pinned.col_slots.len(), scope.clone())
        .expect("witgen: alloc device buffer for the column map");
    col_dev.extend_from_host_slice(&pinned.col_slots)?;
    let mut inslot_dev =
        Buffer::try_with_capacity_in(pinned.input_slots.len().max(1), scope.clone())
            .expect("witgen: alloc device buffer for the input-slot map");
    inslot_dev.extend_from_host_slice(&pinned.input_slots)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone())
        .expect("witgen: alloc device buffer for the packed inputs");
    in_dev.extend_from_host_slice(inputs)?;

    if n_events > 0 {
        unsafe {
            const BLOCK: usize = 64;
            let grid = n_events.div_ceil(BLOCK);
            let args = args!(
                trace.as_mut_ptr(),
                height,
                ops_dev.as_ptr(),
                pinned.ops.len(),
                col_dev.as_ptr(),
                n_cols,
                chip.program.num_inputs,
                inslot_dev.as_ptr(),
                in_dev.as_ptr(),
                n_events
            );
            scope
                .launch_kernel(TaskScope::witgen_interp_slots_kernel(), grid, BLOCK, &args, 0)
                .expect("witgen: launch slot column kernel");
        }
    }

    Ok(DeviceMle::from(trace))
}

/// Slot-indexed FUSED tracegen for WIDE device-dependency gadgets (Mul): the
/// register-allocated counterpart of [`generate_trace_and_lookups`]. One op-DAG pass
/// writes the columns AND accumulates the byte/range lookups into the shared shard
/// histograms via `witgen_fused_slots_kernel`. This is the path the prover actually
/// calls for chips with `supports_device_dependencies` (see `generate_trace_device_with_lookups`).
pub(crate) async fn generate_trace_and_lookups_slots(
    chip: &WitgenChip,
    batch: WitgenBatch<'_>,
    hist: LookupHist,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    // Zeroed trace; only event rows are written (padding rows stay 0 — is_real=0).
    let trace = Tensor::<F, TaskScope>::zeros_in([chip.n_cols(), batch.height], scope.clone());
    generate_trace_and_lookups_slots_into(chip, batch, trace, hist, scope).await
}

/// Like [`generate_trace_and_lookups_slots`] but writes into a caller-provided,
/// already-initialized `trace` — for chips whose padding rows are NOT all-zero
/// (ShiftLeft/ShiftRight broadcast a template across padding; ShaCompress's cyclic
/// octet/index/k pattern). The slot dual of [`generate_trace_and_lookups_into`].
///
/// This is where every fused launch ultimately lands (production default), and it
/// picks the kernel by the STREAMING footprint:
/// 1. `streaming_max <= WITGEN_SMEM_CAP` and empty epilogue →
///    `witgen_fused_streaming_smem_kernel` (wires in `__shared__`);
/// 2. `streaming_max <= WITGEN_MAX_WIRES` and empty epilogue →
///    `witgen_fused_streaming_kernel` (local wires, store-through);
/// 3. otherwise (footprint over cap, or a multi-column epilogue — the kernel
///    epilogue is nat-only) → pinned register-allocated fallback
///    (`witgen_fused_slots_kernel`, columns read out at the end).
pub(crate) async fn generate_trace_and_lookups_slots_into(
    chip: &WitgenChip,
    batch: WitgenBatch<'_>,
    mut trace: Tensor<F, TaskScope>,
    hist: LookupHist,
    scope: &TaskScope,
) -> Result<DeviceMle<F>, CopyError> {
    let WitgenBatch { inputs, n_events, height } = batch;
    let n_cols = chip.n_cols();
    // STREAMING (store-through) shared-memory path: columns written at production,
    // wires resident on-chip. Covers chips whose transient footprint fits the smem
    // cap (iter-073 census: 15/20 <= 24); the multi-column epilogue is nat-only in
    // the kernel, so any field-typed epilogue chip falls back to the pinned path.
    let streaming = &chip.streaming;
    let s_max = streaming.max_slots;
    tracing::debug!(
        target: "witgen_slots",
        streaming_max = s_max,
        epilogue = streaming.epilogue.len(),
        n_cols,
        "witgen slot footprint"
    );
    if (s_max as usize) <= WITGEN_MAX_WIRES && streaming.epilogue.is_empty() {
        let ic_idx: Vec<u32> = streaming.input_cols.iter().map(|&(i, _)| i).collect();
        let ic_col: Vec<u32> = streaming.input_cols.iter().map(|&(_, c)| c).collect();

        let mut ops_dev = Buffer::try_with_capacity_in(streaming.ops.len(), scope.clone())
            .expect("witgen: alloc device buffer for the op-DAG");
        ops_dev.extend_from_host_slice(&streaming.ops)?;
        let mut inslot_dev =
            Buffer::try_with_capacity_in(streaming.input_slots.len().max(1), scope.clone())
                .expect("witgen: alloc device buffer for the input-slot map");
        inslot_dev.extend_from_host_slice(&streaming.input_slots)?;
        let mut ic_idx_dev = Buffer::try_with_capacity_in(ic_idx.len().max(1), scope.clone())
            .expect("witgen: alloc device buffer for the input-column indices");
        ic_idx_dev.extend_from_host_slice(&ic_idx)?;
        let mut ic_col_dev = Buffer::try_with_capacity_in(ic_col.len().max(1), scope.clone())
            .expect("witgen: alloc device buffer for the input-column targets");
        ic_col_dev.extend_from_host_slice(&ic_col)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone())
            .expect("witgen: alloc device buffer for the packed inputs");
        in_dev.extend_from_host_slice(inputs)?;

        if n_events > 0 {
            unsafe {
                // The smem kernel REQUIRES this exact block size (see the const doc).
                const BLOCK: usize = WITGEN_SMEM_BLOCK;
                let grid = n_events.div_ceil(BLOCK);
                let args = args!(
                    trace.as_mut_ptr(),
                    height,
                    ops_dev.as_ptr(),
                    streaming.ops.len(),
                    chip.program.num_inputs,
                    inslot_dev.as_ptr(),
                    ic_idx_dev.as_ptr(),
                    ic_col_dev.as_ptr(),
                    ic_idx.len() as u32,
                    std::ptr::null::<u32>(), // epilogue (empty by gate above)
                    std::ptr::null::<u32>(),
                    0u32,
                    in_dev.as_ptr(),
                    n_events,
                    hist.range,
                    hist.byte
                );
                // Tier by footprint: on-chip shared wires when they fit the smem
                // cap, otherwise the local-wire streaming variant (Keccak 69,
                // Mul 49, SHA 135–211 — all stream; nothing re-pins columns).
                let kernel = if s_max <= WITGEN_SMEM_CAP {
                    TaskScope::witgen_fused_streaming_smem_kernel()
                } else {
                    TaskScope::witgen_fused_streaming_kernel()
                };
                scope
                    .launch_kernel(kernel, grid, BLOCK, &args, 0)
                    .expect("witgen: launch streaming fused kernel");
            }
        }
        return Ok(DeviceMle::from(trace));
    }

    // Pinned fallback: columns held live and read out at the end (local-memory wires).
    let pinned = chip.pinned();

    let mut ops_dev = Buffer::try_with_capacity_in(pinned.ops.len(), scope.clone())
        .expect("witgen: alloc device buffer for the op-DAG");
    ops_dev.extend_from_host_slice(&pinned.ops)?;
    let mut col_dev = Buffer::try_with_capacity_in(pinned.col_slots.len(), scope.clone())
        .expect("witgen: alloc device buffer for the column map");
    col_dev.extend_from_host_slice(&pinned.col_slots)?;
    let mut inslot_dev =
        Buffer::try_with_capacity_in(pinned.input_slots.len().max(1), scope.clone())
            .expect("witgen: alloc device buffer for the input-slot map");
    inslot_dev.extend_from_host_slice(&pinned.input_slots)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone())
        .expect("witgen: alloc device buffer for the packed inputs");
    in_dev.extend_from_host_slice(inputs)?;

    if n_events > 0 {
        unsafe {
            const BLOCK: usize = 64;
            let grid = n_events.div_ceil(BLOCK);
            let args = args!(
                trace.as_mut_ptr(),
                height,
                ops_dev.as_ptr(),
                pinned.ops.len(),
                col_dev.as_ptr(),
                n_cols,
                chip.program.num_inputs,
                inslot_dev.as_ptr(),
                in_dev.as_ptr(),
                n_events,
                hist.range,
                hist.byte
            );
            scope
                .launch_kernel(TaskScope::witgen_fused_slots_kernel(), grid, BLOCK, &args, 0)
                .expect("witgen: launch pinned fused slot kernel");
        }
    }
    Ok(DeviceMle::from(trace))
}

/// Slot-indexed dual of [`accumulate_lookups`] for WIDE gadgets: same shard-histogram
/// accumulation via `witgen_lookup_slots_kernel`, register-allocated so wide gadgets
/// fit. Uses the SAME `allocate_slots(col_wires)` map as the column launch so the two
/// kernels interpret an identical slot-resolved op-DAG.
///
/// CALLERS: only the wide chips' `generate_device_dependencies` impls — a path the
/// prover no longer takes (see the trait doc); retained as the standalone lookup
/// reference for the fused kernels.
pub(crate) async fn accumulate_lookups_slots(
    chip: &WitgenChip,
    inputs: &[u64],
    n_events: usize,
    range_dev: &mut DeviceBuffer<u32>,
    byte_dev: &mut DeviceBuffer<u32>,
    scope: &TaskScope,
) -> Result<(), CopyError> {
    if n_events == 0 {
        return Ok(());
    }
    let pinned = chip.pinned();
    tracing::debug!(
        target: "witgen_slots",
        max_slots = pinned.max_slots,
        streaming_max = chip.streaming.max_slots,
        epilogue = chip.streaming.epilogue.len(),
        n_cols = chip.n_cols(),
        "witgen slot footprint"
    );

    let mut ops_dev = Buffer::try_with_capacity_in(pinned.ops.len(), scope.clone())
        .expect("witgen: alloc device buffer for the op-DAG");
    ops_dev.extend_from_host_slice(&pinned.ops)?;
    let mut inslot_dev =
        Buffer::try_with_capacity_in(pinned.input_slots.len().max(1), scope.clone())
            .expect("witgen: alloc device buffer for the input-slot map");
    inslot_dev.extend_from_host_slice(&pinned.input_slots)?;
    let mut in_dev = Buffer::try_with_capacity_in(inputs.len(), scope.clone())
        .expect("witgen: alloc device buffer for the packed inputs");
    in_dev.extend_from_host_slice(inputs)?;
    unsafe {
        const BLOCK: usize = 64;
        let grid = n_events.div_ceil(BLOCK);
        let args = args!(
            ops_dev.as_ptr(),
            pinned.ops.len(),
            chip.program.num_inputs,
            inslot_dev.as_ptr(),
            in_dev.as_ptr(),
            n_events,
            range_dev.as_mut_ptr(),
            byte_dev.as_mut_ptr()
        );
        scope
            .launch_kernel(TaskScope::witgen_lookup_slots_kernel(), grid, BLOCK, &args, 0)
            .expect("witgen: launch slot lookup kernel");
    }
    Ok(())
}

/// Name of the device-capable chip variant (`None` for chips without a device
/// tracegen impl). Used by the `AR_DEVICE_CHIPS` gate.
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
        // Wide gadget on device via the register-allocated slot kernels (iter-066).
        // Off by default (needs AR_DEVICE_CHIPS=...,Mul); device==CPU trace validated
        // by `test_mul_generate_trace_device`.
        RiscvAir::Mul(_) => "Mul",
        // Widest ALU gadget, un-gated by the STREAMING lowering (pinned 272 slots >
        // the 256 cap; streaming 68 transients, empty epilogue). Fused-only —
        // production routes through `generate_trace_device_with_lookups`. CPU-model
        // validated (columns vs host + lookups vs generate_dependencies) and GPU
        // device==CPU trace validated (`test_divrem_generate_trace_device_fused`,
        // passing on the 4090). Off by default like the rest; e2e crossverify with
        // DivRem in AR_DEVICE_CHIPS before enabling it in any default config.
        RiscvAir::DivRem(_) => "DivRem",
        // iter-071 CPU-side ports — CPU-model validated (columns + lookups); GPU
        // device==CPU trace tests not yet run. Do not enable in AR_DEVICE_CHIPS
        // until the tokio tests pass on device.
        RiscvAir::StateBump(_) => "StateBump",
        RiscvAir::MemoryBump(_) => "MemoryBump",
        // iter-071 ports with passing GPU device==CPU fused-kernel tests
        // (`test_memory_local_fused_kernel`, `test_memory_global_fused_kernel`,
        // `test_syscall_fused_kernel`).
        RiscvAir::MemoryLocal(_) => "MemoryLocal",
        RiscvAir::MemoryGlobalInit(_) => "MemoryGlobalInit",
        RiscvAir::MemoryGlobalFinal(_) => "MemoryGlobalFinal",
        RiscvAir::SyscallCore(_) => "SyscallCore",
        RiscvAir::SyscallPrecompile(_) => "SyscallPrecompile",
        // ECALL instruction chip (iter-076): RTypeReader + 5×IsZero + COMMIT bitmap
        // / digest + HALT/CDP field range checks. Byte-lookup-only deps → fused
        // path. CPU-model validated; GPU device==CPU test not yet run.
        RiscvAir::SyscallInstrs(_) => "SyscallInstrs",
        RiscvAir::KeccakP(_) => "KeccakPermute",
        // Keccak's controller (iter-076): SyscallAddr + 25 AddrAdd + 50 memory
        // accesses. Byte-lookup-only deps → fused path; FUSED-ONLY (streaming
        // lowering; 634-col pinned floor can't fit). CPU-model validated; GPU
        // device==CPU test not yet run.
        RiscvAir::KeccakPControl(_) => "KeccakPermuteControl",
        RiscvAir::Sha256Extend(_) => "ShaExtend",
        RiscvAir::Sha256Compress(_) => "ShaCompress",
        // SHA controllers (iter-076): SyscallAddr + AddrAdd (+ compress state
        // half-words). Narrow chips; byte-lookup-only deps → fused path.
        // CPU-model validated; GPU device==CPU tests not yet run.
        RiscvAir::Sha256ExtendControl(_) => "ShaExtendControl",
        RiscvAir::Sha256CompressControl(_) => "ShaCompressControl",
        _ => return None,
    })
}

/// Runtime gate for the device-tracegen path.
///
/// The device-tracegen DSL (witgen → op-DAG → generic interpreter) is validated
/// for the full RISC-V ALU+memory+control ISA plus SHA/Keccak. e2e A/B of the
/// FINAL tier ladder (fused streaming kernels + on-device Byte/Range build +
/// stream fan-out; `AR_DEVICE_CHIPS=all` vs unset, core mode, proofs verified,
/// RTX 4090, 2026-07-10):
///
/// | program                       | baseline (s) | device (s) | delta  |
/// |-------------------------------|--------------|------------|--------|
/// | keccak256-1mb  (5 shards)     | 2.98–3.01    | 2.82–2.83  | ~-5.5% |
/// | keccak256-3mb  (12 shards)    | 6.96         | 6.51       | ~-6%   |
/// | rsp block 21000000 (70 shards)| 33.86        | 33.51      | ~-1%   |
/// | fibonacci-200m (24 shards)    | 12.41–12.78  | 13.77–14.25| ~+9%   |
///
/// Net: faster on precompile-heavy workloads, noise on RSP-class, slower on the
/// ALU-only fibonacci (residual is per-shard phase seams, not kernel time —
/// analyzed in iter-078; separable follow-up). Kept **off by default** until the
/// kernel-efficiency workstream (input-read coalescing, histogram atomics)
/// lands and the fibonacci seam is closed — only `Global` (the pre-existing
/// baseline device chip) runs on device, matching the baseline. Set
/// `AR_DEVICE_CHIPS` to a comma-list (or `all`) to enable chips for study.
fn device_chip_enabled(name: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::OnceLock;
    static FILTER: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    let filter = FILTER.get_or_init(|| {
        std::env::var("AR_DEVICE_CHIPS")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    });
    match filter {
        None => name == "Global", // default: baseline behavior (only Global on device)
        // `AR_DEVICE_CHIPS=all` enables every chip with a device impl — the canonical
        // parity-A/B config, immune to the env list drifting from the ported set.
        Some(set) => set.contains("all") || set.contains(name),
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
        let Some(name) = device_chip_name(self) else { return false };
        // Fused-only chips have no columns-only kernel (their pinned slot footprint
        // exceeds the kernel cap): with the device dependency path disabled they
        // cannot run on device at all, so fall back to HOST tracegen instead of
        // panicking in `generate_trace_device` at prove time
        // (`AR_DEVICE_CHIPS=all` + `AR_DEVICE_DEPS=0`).
        //
        // DRIFT HAZARD: this list must be extended BY HAND when the next fused-only
        // chip lands (a missed entry re-opens the prove-time panic). It should become
        // a per-chip property when the M-B/M-D macro collapse gives chips a
        // descriptor to hang it on.
        const FUSED_ONLY: [&str; 3] = ["DivRem", "KeccakPermute", "KeccakPermuteControl"];
        if !device_deps_enabled() && FUSED_ONLY.contains(&name) {
            return false;
        }
        device_chip_enabled(name)
    }

    /// Non-fused (columns-only) dispatch. The prover reaches this only for device
    /// chips WITHOUT device dependencies (Global; MemoryLocal/MemoryGlobal*/Syscall*,
    /// whose deps must stay on host) and for every device chip when
    /// `AR_DEVICE_DEPS=0`; fused chips normally route through
    /// `generate_trace_device_with_lookups` instead. Fused-ONLY chips (DivRem,
    /// Keccak*) deliberately `unimplemented!()` their arm's target.
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
            Self::StateBump(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryBump(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryLocal(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::MemoryGlobalInit(chip) | Self::MemoryGlobalFinal(chip) => {
                chip.generate_trace_device(input, output, scope).await
            }
            Self::SyscallCore(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::SyscallPrecompile(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::SyscallInstrs(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Sha256Extend(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Sha256Compress(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Sha256ExtendControl(chip) => {
                chip.generate_trace_device(input, output, scope).await
            }
            Self::Sha256CompressControl(chip) => {
                chip.generate_trace_device(input, output, scope).await
            }
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }

    fn supports_device_dependencies(&self) -> bool {
        // Same gate as main tracegen, but `Global` has no device dependency path
        // (it has no byte lookups; its trace IS built from the global events).
        // MemoryLocal/Syscall*/MemoryGlobal* run the FUSED byte-lookup path like
        // every other device chip; the `GlobalInteractionEvent`s their
        // `generate_dependencies` also emits (septic-curve global table inputs,
        // which no device path can produce) still come from the host — the prover
        // skips these chips in the host dependency pass, and
        // `Machine::generate_dependencies` runs their
        // `generate_global_dependencies` (globals only, no byte lookups) instead.
        // `AR_DEVICE_DEPS=0` disables the device byte-lookup path globally (host
        // generates dependencies) to isolate the device main-trace cost from the
        // dense-histogram readback cost in the e2e bench.
        device_deps_enabled()
            && device_chip_name(self)
                .is_some_and(|n| !matches!(n, "Global") && device_chip_enabled(n))
    }

    /// Standalone lookup-pass dispatch — no production caller (the prover uses the
    /// fused path; see the trait doc). Kept as the reference path for validating the
    /// fused kernels' lookup arms.
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
            Self::StateBump(chip) => dispatch!(chip),
            Self::MemoryBump(chip) => dispatch!(chip),
            Self::SyscallInstrs(chip) => dispatch!(chip),
            Self::KeccakP(chip) => dispatch!(chip),
            Self::KeccakPControl(chip) => dispatch!(chip),
            Self::Sha256Extend(chip) => dispatch!(chip),
            Self::Sha256Compress(chip) => dispatch!(chip),
            Self::Sha256ExtendControl(chip) => dispatch!(chip),
            Self::Sha256CompressControl(chip) => dispatch!(chip),
            Self::MemoryLocal(chip) => dispatch!(chip),
            Self::MemoryGlobalInit(chip) | Self::MemoryGlobalFinal(chip) => dispatch!(chip),
            Self::SyscallCore(chip) | Self::SyscallPrecompile(chip) => dispatch!(chip),
            _ => unimplemented!(),
        }
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
            // Wide gadget on device (iter-066/067): without this arm the fused path gets
            // empty inputs → no Mul trace → failed verification.
            Self::Mul(_) => pk!(input.mul_events, mul::pack_mul_inputs),
            // Fused-only streaming chip (see `device_chip_name`).
            Self::DivRem(_) => pk!(input.divrem_events, divrem::pack_divrem_inputs),
            // ECALL instruction chip (iter-076).
            Self::SyscallInstrs(_) => {
                pk!(input.syscall_events, syscall_instrs::pack_syscall_instr_inputs)
            }
            // iter-071 ports with device dependencies (fused path).
            Self::StateBump(_) => {
                pk!(input.bump_state_events, state_bump::pack_state_bump_inputs)
            }
            Self::MemoryBump(_) => {
                pk!(input.bump_memory_events, memory_bump::pack_memory_bump_inputs)
            }
            // Chips whose host `generate_dependencies` ALSO emits global interaction
            // events: their byte lookups fuse here like any other device chip, while
            // the globals still come from the host `generate_global_dependencies`
            // pass (see `supports_device_dependencies`).
            Self::MemoryLocal(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    let events: Vec<_> = input.get_local_mem_events().collect();
                    memory_local::pack_memory_local_inputs(&events)
                }
            }
            Self::MemoryGlobalInit(chip) | Self::MemoryGlobalFinal(chip) => {
                if height == 0 {
                    Vec::new()
                } else {
                    let (events, previous_addr) =
                        memory_global::sorted_events_and_prev(input, chip.kind);
                    memory_global::pack_memory_global_inputs(&events, previous_addr)
                }
            }
            Self::SyscallCore(chip) | Self::SyscallPrecompile(chip) => {
                if height == 0 {
                    Vec::new()
                } else {
                    let events = syscall::collect_syscall_events(input, chip.shard_kind());
                    syscall::pack_syscall_inputs(&events)
                }
            }
            // Keccak: pack the FULL padded height (padding rows = cyclic dummy pattern).
            Self::KeccakP(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    keccak::pack_keccak_inputs(&keccak::collect_events(input), height)
                }
            }
            // KeccakPermuteControl: one row per event, packed straight from the record.
            Self::KeccakPControl(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    keccak_control::pack_keccak_control_inputs(input)
                }
            }
            // ShaExtend: 48 input rows per event (collect_events handles traps).
            Self::Sha256Extend(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    sha_extend::pack_for_record(input)
                }
            }
            // ShaCompress: 80 input rows per event (pack replays the compression).
            Self::Sha256Compress(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    sha_compress::pack_for_record(input)
                }
            }
            // SHA controllers: one row per event.
            Self::Sha256ExtendControl(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    sha_extend_control::pack_sha_extend_control_inputs(input)
                }
            }
            Self::Sha256CompressControl(_) => {
                if height == 0 {
                    Vec::new()
                } else {
                    sha_compress_control::pack_sha_compress_control_inputs(input)
                }
            }
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
            Self::StateBump(chip) => dispatch!(chip),
            Self::MemoryBump(chip) => dispatch!(chip),
            Self::SyscallInstrs(chip) => dispatch!(chip),
            Self::KeccakP(chip) => dispatch!(chip),
            Self::KeccakPControl(chip) => dispatch!(chip),
            Self::Sha256Extend(chip) => dispatch!(chip),
            // Missing arms here are the iter-067 trap: a `supports_device_dependencies`
            // chip whose fused dispatch falls into `_` hits `unimplemented!()` at prove
            // time. Sha256Compress was missing until iter-076.
            Self::Sha256Compress(chip) => dispatch!(chip),
            Self::Sha256ExtendControl(chip) => dispatch!(chip),
            Self::Sha256CompressControl(chip) => dispatch!(chip),
            // Globals-on-host chips: fused byte lookups here, global events from the
            // host `generate_global_dependencies` pass.
            Self::MemoryLocal(chip) => dispatch!(chip),
            Self::MemoryGlobalInit(chip) | Self::MemoryGlobalFinal(chip) => dispatch!(chip),
            Self::SyscallCore(chip) | Self::SyscallPrecompile(chip) => dispatch!(chip),
            _ => unimplemented!(),
        }
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
            // (the same conventions `interpret_c_lookups` documents), so the scattered
            // host multiplicities land in the same cells the device chips' atomics did.
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
