//! The GPU zerocheck prover.
//!
//! Constraint evaluation runs through the DAG-native IR in `sp1-gpu-air::ir`:
//! each chip's AIR is compiled once to flat bytecode (`compile_chips` +
//! `upload_machine_bytecode`), and the per-round sumcheck (`zerocheck` →
//! `evaluate_zerocheck` / `zerocheck_fix_last_variable`) interprets that
//! bytecode in fused CUDA kernels (`sp1-gpu-sys` `zerocheck/` kernels).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{Buffer, HasBackend};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;

use sp1_gpu_air::ir::{
    analyze_constraints, build_dag, chunk_dag, enumerate_lowerings, lower_column_tile,
    lower_sequential, ChunkBudget, ChunkBytecode, ColumnTileBytecode, DagBuilder, Lowering,
};
use sp1_gpu_cudart::sys::kernels::{
    zerocheck_aggregate_partials_kernel, zerocheck_column_tile_ext_kernel,
    zerocheck_column_tile_kb_kernel, zerocheck_fix_geq_state_kernel,
    zerocheck_fused_sequential_ext_1024_kernel, zerocheck_fused_sequential_ext_128_kernel,
    zerocheck_fused_sequential_ext_256_kernel, zerocheck_fused_sequential_ext_32_kernel,
    zerocheck_fused_sequential_ext_512_kernel, zerocheck_fused_sequential_ext_64_kernel,
    zerocheck_fused_sequential_kb_1024_kernel, zerocheck_fused_sequential_kb_128_kernel,
    zerocheck_fused_sequential_kb_256_kernel, zerocheck_fused_sequential_kb_32_kernel,
    zerocheck_fused_sequential_kb_512_kernel, zerocheck_fused_sequential_kb_64_kernel,
    zerocheck_geq_corrections_kernel, zerocheck_gkr_sweep_ext_kernel,
    zerocheck_gkr_sweep_kb_kernel, zerocheck_pad_adj_1024_kernel, zerocheck_pad_adj_128_kernel,
    zerocheck_pad_adj_256_kernel, zerocheck_pad_adj_32_kernel, zerocheck_pad_adj_512_kernel,
    zerocheck_pad_adj_64_kernel,
};
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceCopy, DevicePoint, TaskScope};
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle};
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::prover::ZerocheckAir;
use sp1_hypercube::{
    AirOpenedValues, Chip, ChipEvaluation, ChipOpenedValues, LogUpEvaluations, ShardOpenedValues,
};

use crate::challenger_update;
use crate::primitives::{evaluate_jagged_fix_last_variable, JaggedFixLastVariableKernel};

// ============================================================================
// Compiled per-chip data — built once per session, reused across all rounds
// and shards.
// ============================================================================

/// One chunk's bytecode + a discriminator for which kernel runs it.
#[derive(Debug, Clone)]
pub(crate) enum CompiledChunk {
    Sequential(ChunkBytecode),
    ColumnTile(ColumnTileBytecode),
}

/// Per-chip compiled program: a list of chunks (Sequential + ColumnTile)
/// plus a final synthesized GKR-correction chunk.
#[derive(Debug, Clone)]
pub(crate) struct CompiledChip {
    pub chip_idx: u32,
    pub name: String,
    pub main_width: u32,
    pub prep_width: u32,
    pub chunks: Vec<CompiledChunk>,
}

/// Index of the synthesized GKR chunk inside `chunks`. Used by the launcher
/// to wire `runtime_coeffs` only to that one chunk's launch.
/// Compile a chip set to per-chip v2 chunks.
///
/// The emitted bytecode is **machine-stable**: it depends only on each chip's
/// AIR, not on the cluster it lands in. In particular, assertion alpha
/// indices are stored *chip-relative* (`0 .. chip.num_constraints`), NOT
/// shifted into the cluster's `powers_of_alpha` table. The cluster-dependent
/// shift (`max_num_constraints - chip.num_constraints`) is instead applied at
/// kernel-launch time via `ChunkMetaC::chip_alpha_offset` (fused Sequential
/// kernel) or by offsetting the `powers_of_alpha` pointer (ColumnTile). This
/// lets the compiled+uploaded bytecode be cached once per machine and reused
/// across every shard and cluster.
///
/// The synthesized GKR chunk (only for chips with no Sequential carrier)
/// stores the chip-relative index `num_constraints - 1`, which the same
/// runtime shift maps onto the `powers_of_alpha` slot holding `EF::one()`.
pub(crate) fn compile_chips<A>(
    chips: &BTreeSet<Chip<Felt, A>>,
    budget: ChunkBudget,
) -> Vec<CompiledChip>
where
    A: MachineAir<Felt> + for<'a> Air<DagBuilder<'a>>,
{
    let t_compile = std::time::Instant::now();

    let mut out = Vec::with_capacity(chips.len());
    for (i, chip) in chips.iter().enumerate() {
        let air: &A = chip.air.as_ref();
        let dag = build_dag(air);
        let infos = analyze_constraints(&dag);
        let chunks_meta = chunk_dag(&infos, &budget);

        let mut compiled_chunks: Vec<CompiledChunk> = Vec::new();
        for chunk in &chunks_meta {
            let lowerings = enumerate_lowerings(chunk, &infos, &dag);
            // Prefer ColumnTile if it applies; fall back to Sequential.
            let mut placed = false;
            if let Some(plan) = lowerings.iter().find_map(|l| match l {
                Lowering::ColumnTile(p) => Some(p),
                _ => None,
            }) {
                if let Some(bc) = lower_column_tile(chunk, &infos, &dag, plan) {
                    // `bc.terms[*].alpha_idx` stays chip-relative; the
                    // cluster shift is applied at launch.
                    compiled_chunks.push(CompiledChunk::ColumnTile(bc));
                    placed = true;
                }
            }
            if !placed {
                let plan = lowerings
                    .iter()
                    .find_map(|l| match l {
                        Lowering::Sequential(p) => Some(p),
                        _ => None,
                    })
                    .expect("every chunk must have a Sequential lowering");
                let bc = lower_sequential(chunk, &infos, &dag, plan);
                // `bc.asserts[*].1` (alpha index) stays chip-relative; the
                // cluster shift is applied at launch.
                // The fused sequential kernel templates cap `MAX_REGS` at
                // 1024; `fused_sequential_kernel_for` silently clamps to
                // the 1024 template, so a chunk exceeding it would OOB-write
                // its per-thread `regs[]` array. Trip loudly here instead —
                // the chunker's leaf budget should keep us well under, but
                // a `CHUNKER_MAX_LEAFSET` env override (or a future
                // `oversize_singleton` escape valve) could otherwise hit
                // this silently. See review bug #6.
                const MAX_FUSED_REGS: u16 = 1024;
                assert!(
                    bc.max_reg <= MAX_FUSED_REGS,
                    "chip {}: chunk max_reg={} exceeds fused-kernel cap ({}); \
                     reduce CHUNKER_MAX_LEAFSET or implement the oversize-singleton \
                     escape valve",
                    air.name(),
                    bc.max_reg,
                    MAX_FUSED_REGS,
                );
                if std::env::var("SP1_GPU_DEBUG_MAXREG").is_ok() {
                    eprintln!(
                        "compile chip={} max_reg={} n_instrs={} n_asserts={}",
                        air.name(),
                        bc.max_reg,
                        bc.instrs.len(),
                        bc.asserts.len()
                    );
                }
                compiled_chunks.push(CompiledChunk::Sequential(bc));
            }
        }

        // Inline-GKR carrier selection. The first Sequential chunk of the
        // chip carries the column-sweep widths so the per-row interp loop
        // shares L1 with the constraint leaf reads — `build_seq_tiers`
        // zeroes these out for chips wider than `WIDE_GKR_THRESHOLD`,
        // routing them through the dedicated `zerocheck_gkr_sweep` kernel
        // instead. Chips without a Sequential carrier (ColumnTile-only)
        // get GKR exclusively from the dedicated kernel — see
        // `gkr_active_chips` in `initialize_zerocheck_poly`.
        let main_width = air.width() as u32;
        let prep_width = air.preprocessed_width() as u32;
        if let Some(carrier_bc) = compiled_chunks.iter_mut().find_map(|c| match c {
            CompiledChunk::Sequential(bc) => Some(bc),
            _ => None,
        }) {
            carrier_bc.gkr_main_width = main_width;
            carrier_bc.gkr_prep_width = prep_width;
        }

        out.push(CompiledChip {
            chip_idx: i as u32,
            name: air.name().to_string(),
            main_width,
            prep_width,
            chunks: compiled_chunks,
        });
    }
    if std::env::var("SP1_GPU_ZEROCHECK_TIMING").is_ok() {
        tracing::info!("compile_chips: {} chips in {:?}", out.len(), t_compile.elapsed());
    }
    out
}

// ============================================================================
// Device-uploaded per-chunk buffers — built once per shard.
// ============================================================================

/// Shard-static per-chunk descriptor uploaded ONCE per shard. Layout must
/// match `struct ChunkStatic` in `include/zerocheck/sequential.cuh`.
///
/// Per-chunk fields that only depend on the chunk's bytecode + the shard's
/// chip set (i.e. don't change between rounds) live here. Per-round chip
/// state — trace pointers and current height — lives in [`ChipLayoutC`],
/// indexed by `chip_idx`. The kernel composes them via the per-block
/// dispatch descriptor [`BlockDispatchC`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChunkStaticC {
    pub instrs: *const sp1_gpu_air::ir::DagInstr,
    pub leaves: *const sp1_gpu_air::ir::LeafRef,
    pub consts: *const Felt,
    pub publics: *const u32,
    pub assert_regs: *const u16,
    pub assert_alphas: *const u32,
    pub n_instrs: u32,
    pub n_asserts: u32,
    pub chip_idx: u32,
    /// Carrier-chunk inline GKR widths. Set non-zero ONLY for narrow chips
    /// (total width ≤ `WIDE_GKR_THRESHOLD`) where keeping the column sweep
    /// inline preserves L1 locality with constraint reads. Wide chips get
    /// GKR via `zerocheck_gkr_sweep` and have these zeroed here.
    pub gkr_main_width: u32,
    pub gkr_prep_width: u32,
    /// Cluster-dependent shift added to every chip-relative alpha index in
    /// this chunk's bytecode before indexing `powers_of_alpha`.
    pub chip_alpha_offset: u32,
}

/// Per-chip GKR widths held on device. Indexed by `chip_idx`; shard-static
/// (widths don't depend on per-round fold). Mirrors `ChipGkrInfo` in
/// `sys/include/zerocheck/gkr_sweep.cuh`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChipGkrInfoC {
    pub main_width: u32,
    pub prep_width: u32,
}

// SAFETY: holds raw device pointers; the kernel dereferences them on the GPU
// after we copy the struct over. Send/Sync is fine for our usage.
unsafe impl Send for ChunkStaticC {}
unsafe impl Sync for ChunkStaticC {}

/// Per-round per-chip trace pointers + height. Layout must match
/// `struct ChipLayout` in `include/zerocheck/sequential.cuh`.
///
/// Built per round from the jagged structure; the kernel reads it via
/// `chip_layouts[chunk_static.chip_idx]`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChipLayoutC {
    pub main_ptr: u64,
    pub preprocessed_ptr: u64,
    pub height: u32,
    pub _pad: u32,
}

/// Per-block dispatch entry. One per launched block per tier; the kernel
/// reads `dispatch[blockIdx.x]` once and processes `n_rows` rows of the
/// referenced chunk starting at `row_offset`. Replaces the old per-row
/// `upper_bound` binary search on `row_starts`.
///
/// Layout must match `struct BlockDispatch` in
/// `include/zerocheck/sequential.cuh`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockDispatchC {
    pub chunk_id: u32,
    pub row_offset: u32,
    pub n_rows: u32,
}

/// Per-chip VirtualGeq state held on device. Mirrors `VirtualGeqState` in
/// `sys/include/zerocheck/geq_corrections.cuh` and the host
/// `slop_multilinear::VirtualGeq<Ext>` struct it replaces.
///
/// Built once per shard from the initial heights, then mutated in place by
/// the `zerocheck_fix_geq_state` kernel after each fold. The recurrence
/// matches `VirtualGeq::fix_last_variable` bit-for-bit so the device state
/// stays identical to what the host loop used to produce.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtualGeqStateC {
    pub threshold: u32,
    pub num_vars: u32,
    pub geq_coefficient: Ext,
    pub eq_coefficient: Ext,
}

/// A per-chunk view into the flat machine-wide bytecode buffers
/// (`MachineBytecode`). Holds raw device pointers, not owned allocations —
/// the backing memory lives in the `MachineBytecode` that contains this
/// struct, so a view is valid exactly as long as that machine bytecode is.
#[derive(Clone, Copy)]
pub(crate) struct ChunkDeviceBufs {
    pub kind: ChunkKind,
    // Common
    pub leaves: *const sp1_gpu_air::ir::LeafRef,
    pub consts: *const Felt,
    pub publics: *const u32,
    // Sequential-only (dummy-but-valid pointer + zero counts for ColumnTile)
    pub instrs: *const sp1_gpu_air::ir::DagInstr,
    pub assert_regs: *const u16,
    pub assert_alphas: *const u32,
    pub max_reg: u16,
    pub n_instrs: u32,
    pub n_asserts: u32,
    /// Sequential chunks that carry the chip's GKR sweep. When > 0, the
    /// kernel appends `Σ_i gkr_powers[i] · col_i` over (main_w main cols,
    /// then prep_w prep cols) after the bytecode + asserts pass, sharing
    /// column reads with the constraint bytecode.
    pub gkr_main_width: u32,
    pub gkr_prep_width: u32,
    // ColumnTile-only (dummy-but-valid pointer + zero count for Sequential)
    pub terms: *const sp1_gpu_air::ir::ColumnTermEntry,
    pub n_terms: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChunkKind {
    Sequential,
    ColumnTile,
}

/// Per-chip device views into the flat machine bytecode.
#[derive(Clone)]
pub(crate) struct CompiledChipDevice {
    pub chip_idx: u32,
    pub main_width: u32,
    pub prep_width: u32,
    pub chunks: Vec<ChunkDeviceBufs>,
}

/// The whole machine's compiled v2 bytecode, uploaded once (at prover
/// construction) into a small fixed number of flat device buffers.
///
/// Every chunk of every chip is concatenated, per array type, into one of
/// the seven `flat_*` buffers; each chunk records pointers into them via
/// `ChunkDeviceBufs`. This replaces the old per-shard, per-chunk upload
/// (~7 tiny allocations × every chunk × every shard) with 7 allocations
/// uploaded exactly once per machine.
pub struct MachineBytecode {
    // Flat buffers — own the device memory the `ChunkDeviceBufs` views point
    // into. Never read directly; kept alive for the views' sake.
    _flat_instrs: Buffer<sp1_gpu_air::ir::DagInstr, TaskScope>,
    _flat_leaves: Buffer<sp1_gpu_air::ir::LeafRef, TaskScope>,
    _flat_consts: Buffer<Felt, TaskScope>,
    _flat_publics: Buffer<u32, TaskScope>,
    _flat_assert_regs: Buffer<u16, TaskScope>,
    _flat_assert_alphas: Buffer<u32, TaskScope>,
    _flat_terms: Buffer<sp1_gpu_air::ir::ColumnTermEntry, TaskScope>,
    /// One entry per machine chip, in machine chip order.
    pub(crate) chips: Vec<CompiledChipDevice>,
    /// Chip name → index into `chips`, for per-shard subset selection.
    pub(crate) chip_index: BTreeMap<String, usize>,
}

// SAFETY: `ChunkDeviceBufs`/`CompiledChipDevice` hold raw device pointers
// into the `_flat_*` buffers owned by the same `MachineBytecode`. They are
// only ever dereferenced on the GPU after being copied across, and the
// backing buffers share this struct's lifetime. We never mutate through the
// pointers on the host.
unsafe impl Send for MachineBytecode {}
unsafe impl Sync for MachineBytecode {}

/// Compile + upload the entire machine's bytecode once. Call at prover
/// construction; the result is reused for every shard and every cluster.
pub fn upload_machine_bytecode<A>(
    chips: &BTreeSet<Chip<Felt, A>>,
    budget: ChunkBudget,
    scope: &TaskScope,
) -> MachineBytecode
where
    A: MachineAir<Felt> + for<'a> Air<DagBuilder<'a>>,
{
    upload_compiled_bytecode(compile_chips(chips, budget), scope)
}

/// Flatten + upload an already-compiled set of chips. Split out of
/// `upload_machine_bytecode` so scaling tests can feed a synthetically large
/// chip list without paying repeated AIR compilation.
pub(crate) fn upload_compiled_bytecode(
    compiled: Vec<CompiledChip>,
    scope: &TaskScope,
) -> MachineBytecode {
    // ---- Pass 1: concatenate every chunk's arrays into flat host vecs. ----
    let mut flat_instrs: Vec<sp1_gpu_air::ir::DagInstr> = Vec::new();
    let mut flat_leaves: Vec<sp1_gpu_air::ir::LeafRef> = Vec::new();
    let mut flat_consts: Vec<Felt> = Vec::new();
    let mut flat_publics: Vec<u32> = Vec::new();
    let mut flat_assert_regs: Vec<u16> = Vec::new();
    let mut flat_assert_alphas: Vec<u32> = Vec::new();
    let mut flat_terms: Vec<sp1_gpu_air::ir::ColumnTermEntry> = Vec::new();

    // Per-chunk (offset, len) into each flat vec, recorded in pass 1 and
    // resolved to pointers in pass 2 (after the flat buffers are uploaded).
    struct ChunkOffsets {
        kind: ChunkKind,
        leaves: (usize, usize),
        consts: (usize, usize),
        publics: (usize, usize),
        instrs: (usize, usize),
        assert_regs: (usize, usize),
        assert_alphas: (usize, usize),
        terms: (usize, usize),
        max_reg: u16,
        gkr_main_width: u32,
        gkr_prep_width: u32,
    }
    let mut chip_offsets: Vec<Vec<ChunkOffsets>> = Vec::with_capacity(compiled.len());

    // Append `src` to `dst`, returning the (offset, len) of the appended run.
    fn extend_flat<T: Copy>(dst: &mut Vec<T>, src: &[T]) -> (usize, usize) {
        let off = dst.len();
        dst.extend_from_slice(src);
        (off, src.len())
    }

    for chip in &compiled {
        let mut chunks = Vec::with_capacity(chip.chunks.len());
        for c in chip.chunks.iter() {
            chunks.push(match c {
                CompiledChunk::Sequential(bc) => {
                    let regs: Vec<u16> = bc.asserts.iter().map(|&(r, _)| r).collect();
                    let alphas: Vec<u32> = bc.asserts.iter().map(|&(_, a)| a).collect();
                    ChunkOffsets {
                        kind: ChunkKind::Sequential,
                        leaves: extend_flat(&mut flat_leaves, &bc.leaves),
                        consts: extend_flat(&mut flat_consts, &bc.consts),
                        publics: extend_flat(&mut flat_publics, &bc.publics),
                        instrs: extend_flat(&mut flat_instrs, &bc.instrs),
                        assert_regs: extend_flat(&mut flat_assert_regs, &regs),
                        assert_alphas: extend_flat(&mut flat_assert_alphas, &alphas),
                        terms: (flat_terms.len(), 0),
                        max_reg: bc.max_reg,
                        gkr_main_width: bc.gkr_main_width,
                        gkr_prep_width: bc.gkr_prep_width,
                    }
                }
                CompiledChunk::ColumnTile(bc) => ChunkOffsets {
                    kind: ChunkKind::ColumnTile,
                    leaves: extend_flat(&mut flat_leaves, &bc.leaves),
                    consts: extend_flat(&mut flat_consts, &bc.consts),
                    publics: extend_flat(&mut flat_publics, &bc.publics),
                    instrs: (flat_instrs.len(), 0),
                    assert_regs: (flat_assert_regs.len(), 0),
                    assert_alphas: (flat_assert_alphas.len(), 0),
                    terms: extend_flat(&mut flat_terms, &bc.terms),
                    max_reg: 0,
                    gkr_main_width: 0,
                    gkr_prep_width: 0,
                },
            });
        }
        chip_offsets.push(chunks);
    }

    // ---- Upload the seven flat buffers (≥1 element so the base pointer is
    // never null even for an array type no chunk uses). ----
    fn upload_flat<T: Copy + 'static>(v: &mut Vec<T>, scope: &TaskScope) -> Buffer<T, TaskScope> {
        if v.is_empty() {
            // POD `#[repr(C)]` bytecode structs — an all-zero element is a
            // valid (never-dereferenced) placeholder so the base pointer of
            // an unused array type is non-null.
            v.push(unsafe { std::mem::zeroed() });
        }
        DeviceBuffer::from_host_slice(v, scope).unwrap().into_inner()
    }
    if std::env::var("SP1_GPU_ZEROCHECK_TIMING").is_ok() {
        let mb = |n: usize, sz: usize| (n * sz) as f64 / (1024.0 * 1024.0);
        tracing::info!(
            "upload_compiled_bytecode: {} chips, flat bytes — instrs={:.1}M leaves={:.1}M \
             consts={:.1}M publics={:.1}M assert_regs={:.1}M assert_alphas={:.1}M terms={:.1}M",
            compiled.len(),
            mb(flat_instrs.len(), std::mem::size_of::<sp1_gpu_air::ir::DagInstr>()),
            mb(flat_leaves.len(), std::mem::size_of::<sp1_gpu_air::ir::LeafRef>()),
            mb(flat_consts.len(), std::mem::size_of::<Felt>()),
            mb(flat_publics.len(), 4),
            mb(flat_assert_regs.len(), 2),
            mb(flat_assert_alphas.len(), 4),
            mb(flat_terms.len(), std::mem::size_of::<sp1_gpu_air::ir::ColumnTermEntry>()),
        );
    }
    let flat_instrs_buf = upload_flat(&mut flat_instrs, scope);
    let flat_leaves_buf = upload_flat(&mut flat_leaves, scope);
    let flat_consts_buf = upload_flat(&mut flat_consts, scope);
    let flat_publics_buf = upload_flat(&mut flat_publics, scope);
    let flat_assert_regs_buf = upload_flat(&mut flat_assert_regs, scope);
    let flat_assert_alphas_buf = upload_flat(&mut flat_assert_alphas, scope);
    let flat_terms_buf = upload_flat(&mut flat_terms, scope);

    // ---- Pass 2: resolve offsets to device pointers. ----
    let instrs_base = flat_instrs_buf.as_ptr();
    let leaves_base = flat_leaves_buf.as_ptr();
    let consts_base = flat_consts_buf.as_ptr();
    let publics_base = flat_publics_buf.as_ptr();
    let assert_regs_base = flat_assert_regs_buf.as_ptr();
    let assert_alphas_base = flat_assert_alphas_buf.as_ptr();
    let terms_base = flat_terms_buf.as_ptr();

    let mut device_chips = Vec::with_capacity(compiled.len());
    let mut chip_index = BTreeMap::new();
    for (chip, offsets) in compiled.iter().zip(chip_offsets.iter()) {
        let chunks = offsets
            .iter()
            .map(|o| ChunkDeviceBufs {
                kind: o.kind,
                leaves: unsafe { leaves_base.add(o.leaves.0) },
                consts: unsafe { consts_base.add(o.consts.0) },
                publics: unsafe { publics_base.add(o.publics.0) },
                instrs: unsafe { instrs_base.add(o.instrs.0) },
                assert_regs: unsafe { assert_regs_base.add(o.assert_regs.0) },
                assert_alphas: unsafe { assert_alphas_base.add(o.assert_alphas.0) },
                terms: unsafe { terms_base.add(o.terms.0) },
                max_reg: o.max_reg,
                n_instrs: o.instrs.1 as u32,
                n_asserts: o.assert_regs.1 as u32,
                gkr_main_width: o.gkr_main_width,
                gkr_prep_width: o.gkr_prep_width,
                n_terms: o.terms.1 as u32,
            })
            .collect();
        chip_index.insert(chip.name.clone(), device_chips.len());
        device_chips.push(CompiledChipDevice {
            chip_idx: chip.chip_idx,
            main_width: chip.main_width,
            prep_width: chip.prep_width,
            chunks,
        });
    }

    MachineBytecode {
        _flat_instrs: flat_instrs_buf,
        _flat_leaves: flat_leaves_buf,
        _flat_consts: flat_consts_buf,
        _flat_publics: flat_publics_buf,
        _flat_assert_regs: flat_assert_regs_buf,
        _flat_assert_alphas: flat_assert_alphas_buf,
        _flat_terms: flat_terms_buf,
        chips: device_chips,
        chip_index,
    }
}

// ============================================================================
// Per-round poly state (parallel to v1's ZeroCheckJaggedPoly).
// ============================================================================

pub(crate) struct ZeroCheckJaggedPoly<'b, K: Field> {
    pub data: Cow<'b, JaggedTraceMle<K, TaskScope>>,
    /// This shard's chips, as pointer-views into `machine_bytecode`.
    pub compiled: Vec<CompiledChipDevice>,
    /// The machine-wide flat bytecode the `compiled` views point into. Held
    /// here so the device buffers outlive every round of this shard.
    pub machine_bytecode: Arc<MachineBytecode>,
    pub eq_adjustment: Ext,
    pub zeta: Point<Ext>,
    pub claim: Ext,
    pub padded_row_adjustment_host: Vec<Ext>,
    pub public_values: Buffer<Felt, TaskScope>,
    pub powers_of_alpha: Buffer<Ext, TaskScope>,
    pub gkr_powers: Buffer<Ext, TaskScope>,
    pub powers_of_lambda: Buffer<Ext, TaskScope>,
    pub chip_main_ptrs: Vec<u64>,
    pub chip_preprocessed_ptrs: Vec<u64>,
    pub chip_heights: Vec<u32>,
    /// Per-chip shift into the cluster's reversed `powers_of_alpha` table:
    /// `max_num_constraints - chip.num_constraints`. The compiled bytecode
    /// stores chip-relative alpha indices; this shift is applied at launch
    /// (see `compile_chips`). Indexed by `chip_idx`.
    pub chip_alpha_offset: Vec<u32>,
    /// Per-shard, per-tier precomputed kernel-launch state.
    pub seq_tiers: [SeqTierStatic; 2],
    /// Per-chip geq state on device. One entry per active chip, indexed by
    /// `chip_idx`. Uploaded at shard init then mutated in place by the
    /// `zerocheck_fix_geq_state` kernel after each fold — no host iteration
    /// per round.
    pub chip_geq_state_dev: Buffer<VirtualGeqStateC, TaskScope>,
    /// Per-chip padded-row adjustment on device, indexed by `chip_idx`.
    /// Shard-static (computed once via the CPU folder against a zero trace).
    pub chip_pad_adj_dev: Buffer<Ext, TaskScope>,
    /// Chip indices that should receive a geq correction this shard —
    /// chips with at least one Sequential carrier and a non-zero `pad_adj`.
    /// Shard-static; `None` iff `n_geq_chips == 0`.
    pub geq_chip_indices_dev: Option<Buffer<u32, TaskScope>>,
    /// Number of chips in `geq_chip_indices_dev`. Drives the grid size of
    /// `zerocheck_geq_corrections`.
    pub n_geq_chips: usize,
    /// Per-chip GKR widths on device, indexed by `chip_idx`. Shard-static.
    pub chip_gkr_info_dev: Buffer<ChipGkrInfoC, TaskScope>,
    /// Chips that participate in GKR (any chip with main_width > 0 or
    /// prep_width > 0). Used as the per-row mapping for the GKR dispatch
    /// table built each round.
    pub gkr_active_chips: Vec<u32>,

    // ---- Per-round buffer caches (grow-only) ----
    //
    // The launcher's per-round host→device uploads (chip layouts, dispatch
    // tables) used to allocate a fresh `DeviceBuffer` every round. With
    // device-side allocator pools off, that's a CUDA malloc per upload per
    // round — small at current scale but linear in chips × rounds and pure
    // waste relative to reusing one buffer with `clear()` +
    // `extend_from_host_slice()`. These caches hold the prior round's
    // buffer and refill in place; only re-allocate when the new payload
    // exceeds the cached capacity.
    pub cached_chip_layouts_buf: Option<Buffer<ChipLayoutC, TaskScope>>,
    pub cached_seq_dispatch: [Option<Buffer<BlockDispatchC, TaskScope>>; 2],
    pub cached_gkr_dispatch: Option<Buffer<BlockDispatchC, TaskScope>>,
}

/// Shard-static data for one fused-kernel tier (low-reg / high-reg).
///
/// The `ChunkStaticC` array is built once when the shard's chips are known
/// and uploaded once — the kernel reads from it every round without further
/// host involvement. `chip_indices` mirrors the static array so the per-round
/// dispatch builder can look up each chunk's current `chip_height` cheaply.
pub(crate) struct SeqTierStatic {
    /// Per-chunk static descriptors in tier order. Index `i` here corresponds
    /// to `chunk_id = i` in `BlockDispatchC`.
    pub static_host: Vec<ChunkStaticC>,
    /// Same length as `static_host`; the chip_idx for chunk `i`, kept in
    /// host memory so dispatch building can look up `chip_heights[chip_idx]`.
    pub chip_indices: Vec<u32>,
    /// Worst-case `max_reg` across all chunks in this tier — drives the
    /// kernel template choice at launch.
    pub max_reg: u16,
    /// Device buffer holding `static_host`; uploaded once per shard, reused
    /// every round.
    pub static_buf: Option<Buffer<ChunkStaticC, TaskScope>>,
}

/// Per-trace-element-type kernel selection. Round 0 uses `K = Felt`; rounds
/// 1+ use `K = Ext` after the trace is folded into the extension field.
pub(crate) trait EvalKernels<K: Field> {
    fn column_tile_kernel() -> KernelPtr;
    /// Tiered fused dispatch kernel. The launcher partitions chunks into
    /// tiers by their `max_reg` and launches one kernel per non-empty
    /// tier so each kernel's local register array is sized to its tier's
    /// worst case.
    fn fused_sequential_kernel_for(max_reg_in_tier: u16) -> KernelPtr;
    /// Per-chip GKR column sweep — one block per (chip, row-tile), warp-
    /// per-row with lane-strided column reduction so wide chips scale.
    fn gkr_sweep_kernel() -> KernelPtr;
}

impl EvalKernels<Felt> for TaskScope {
    fn column_tile_kernel() -> KernelPtr {
        unsafe { zerocheck_column_tile_kb_kernel() }
    }
    fn fused_sequential_kernel_for(max_reg_in_tier: u16) -> KernelPtr {
        unsafe {
            if max_reg_in_tier <= 32 {
                zerocheck_fused_sequential_kb_32_kernel()
            } else if max_reg_in_tier <= 64 {
                zerocheck_fused_sequential_kb_64_kernel()
            } else if max_reg_in_tier <= 128 {
                zerocheck_fused_sequential_kb_128_kernel()
            } else if max_reg_in_tier <= 256 {
                zerocheck_fused_sequential_kb_256_kernel()
            } else if max_reg_in_tier <= 512 {
                zerocheck_fused_sequential_kb_512_kernel()
            } else {
                zerocheck_fused_sequential_kb_1024_kernel()
            }
        }
    }
    fn gkr_sweep_kernel() -> KernelPtr {
        unsafe { zerocheck_gkr_sweep_kb_kernel() }
    }
}

impl EvalKernels<Ext> for TaskScope {
    fn column_tile_kernel() -> KernelPtr {
        unsafe { zerocheck_column_tile_ext_kernel() }
    }
    fn fused_sequential_kernel_for(max_reg_in_tier: u16) -> KernelPtr {
        unsafe {
            if max_reg_in_tier <= 32 {
                zerocheck_fused_sequential_ext_32_kernel()
            } else if max_reg_in_tier <= 64 {
                zerocheck_fused_sequential_ext_64_kernel()
            } else if max_reg_in_tier <= 128 {
                zerocheck_fused_sequential_ext_128_kernel()
            } else if max_reg_in_tier <= 256 {
                zerocheck_fused_sequential_ext_256_kernel()
            } else if max_reg_in_tier <= 512 {
                zerocheck_fused_sequential_ext_512_kernel()
            } else {
                zerocheck_fused_sequential_ext_1024_kernel()
            }
        }
    }
    fn gkr_sweep_kernel() -> KernelPtr {
        unsafe { zerocheck_gkr_sweep_ext_kernel() }
    }
}

// ============================================================================
// Build the initial poly state for round 0.
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub(crate) fn initialize_zerocheck_poly<'b, A>(
    data: &'b JaggedTraceMle<Felt, TaskScope>,
    chips: &BTreeSet<Chip<Felt, A>>,
    compiled_chips_dev: Vec<CompiledChipDevice>,
    machine_bytecode: Arc<MachineBytecode>,
    initial_heights: Vec<u32>,
    public_values: Vec<Felt>,
    powers_of_alpha: Vec<Ext>,
    gkr_powers: Vec<Ext>,
    powers_of_lambda: Vec<Ext>,
    zeta: Point<Ext>,
    claim: Ext,
) -> ZeroCheckJaggedPoly<'b, Felt>
where
    A: MachineAir<Felt>,
{
    let scope = data.dense().backend();

    let (chip_main_ptrs, chip_preprocessed_ptrs, chip_heights) = compute_chip_offsets(data, chips);

    // Per-chip launch-time shift into the reversed `powers_of_alpha` table.
    let max_num_constraints =
        chips.iter().map(|c| c.num_constraints).max().unwrap_or(1).max(1) as u32;
    let chip_alpha_offset: Vec<u32> =
        chips.iter().map(|c| max_num_constraints - c.num_constraints as u32).collect();

    let public_values_device =
        DeviceBuffer::from_host(&Buffer::from(public_values), scope).unwrap().into_inner();
    let powers_of_alpha_device =
        DeviceBuffer::from_host(&Buffer::from(powers_of_alpha), scope).unwrap().into_inner();
    let gkr_powers_device =
        DeviceBuffer::from_host(&Buffer::from(gkr_powers), scope).unwrap().into_inner();
    let powers_of_lambda_device =
        DeviceBuffer::from_host(&Buffer::from(powers_of_lambda), scope).unwrap().into_inner();

    let seq_tiers = build_seq_tiers(&compiled_chips_dev, &chip_alpha_offset, scope);

    // ---- Per-chip GKR info on device ----
    //
    // The GKR column sweep (formerly inlined in the carrier chunk) is now
    // its own kernel that runs uniformly for every chip with non-zero
    // width. This also fixes the latent gap where ColumnTile-only chips
    // never got GKR.
    let chip_gkr_info_host: Vec<ChipGkrInfoC> = compiled_chips_dev
        .iter()
        .map(|chip| ChipGkrInfoC { main_width: chip.main_width, prep_width: chip.prep_width })
        .collect();
    let chip_gkr_info_dev =
        DeviceBuffer::from_host_slice(&chip_gkr_info_host, scope).unwrap().into_inner();
    // The decoupled GKR kernel runs for any chip whose carrier-chunk inline
    // GKR doesn't (or can't) fire: wide chips (`build_seq_tiers` zeroed
    // their inline widths) and chips that lack a Sequential carrier
    // entirely (ColumnTile-only — narrow or wide, neither path runs
    // otherwise). Both groups need decoupled coverage.
    let gkr_active_chips: Vec<u32> = compiled_chips_dev
        .iter()
        .filter(|chip| chip.main_width + chip.prep_width > 0)
        .filter(|chip| {
            let has_seq_carrier =
                chip.chunks.iter().any(|c| matches!(c.kind, ChunkKind::Sequential));
            chip_uses_decoupled_gkr(chip.main_width, chip.prep_width) || !has_seq_carrier
        })
        .map(|chip| chip.chip_idx)
        .collect();

    // ---- Per-chip geq state on device ----
    //
    // Initial state matches `VirtualGeq::new(initial_height, 1, 0, num_vars)`
    // per chip. The state is mutated in place by `zerocheck_fix_geq_state`
    // each round, never touched by the host again.
    let num_vars = zeta.dimension() as u32;
    let geq_state_host: Vec<VirtualGeqStateC> = initial_heights
        .iter()
        .map(|&h| VirtualGeqStateC {
            threshold: h,
            num_vars,
            geq_coefficient: Ext::one(),
            eq_coefficient: Ext::zero(),
        })
        .collect();
    let chip_geq_state_dev =
        DeviceBuffer::from_host_slice(&geq_state_host, scope).unwrap().into_inner();

    // ---- padded_row_adjustment on device ----
    //
    // Replaces the per-chip CPU `chip.air.eval` loop that used to run at
    // shard init. The bytecode interpreter knows how to evaluate every
    // chip's constraints; we just run it at the all-zero trace and sum
    // asserts. ColumnTile chunks contribute exactly zero at the zero trace
    // (every term is `coeff · 0`), so summing only Sequential chunks is
    // mathematically exact.
    let padded_row_adjustment = compute_padded_row_adjustment(
        compiled_chips_dev.len(),
        &seq_tiers,
        &public_values_device,
        &powers_of_alpha_device,
        scope,
    );
    let chip_pad_adj_dev =
        DeviceBuffer::from_host_slice(&padded_row_adjustment, scope).unwrap().into_inner();

    // Filter chips that should get a geq correction: must have a Sequential
    // carrier (matches the predicate the old in-kernel geq gated on) and a
    // non-zero `pad_adj` (otherwise the contribution is identically zero).
    let geq_chip_indices_host: Vec<u32> = compiled_chips_dev
        .iter()
        .filter(|chip| {
            chip.chunks.iter().any(|c| matches!(c.kind, ChunkKind::Sequential))
                && padded_row_adjustment[chip.chip_idx as usize] != Ext::zero()
        })
        .map(|chip| chip.chip_idx)
        .collect();
    let n_geq_chips = geq_chip_indices_host.len();
    let geq_chip_indices_dev = if n_geq_chips > 0 {
        Some(DeviceBuffer::from_host_slice(&geq_chip_indices_host, scope).unwrap().into_inner())
    } else {
        None
    };

    ZeroCheckJaggedPoly {
        data: Cow::Borrowed(data),
        compiled: compiled_chips_dev,
        machine_bytecode,
        eq_adjustment: Ext::one(),
        zeta,
        claim,
        padded_row_adjustment_host: padded_row_adjustment,
        public_values: public_values_device,
        powers_of_alpha: powers_of_alpha_device,
        gkr_powers: gkr_powers_device,
        powers_of_lambda: powers_of_lambda_device,
        chip_main_ptrs,
        chip_preprocessed_ptrs,
        chip_heights,
        chip_alpha_offset,
        seq_tiers,
        chip_geq_state_dev,
        chip_pad_adj_dev,
        geq_chip_indices_dev,
        n_geq_chips,
        chip_gkr_info_dev,
        gkr_active_chips,
        cached_chip_layouts_buf: None,
        cached_seq_dispatch: [None, None],
        cached_gkr_dispatch: None,
    }
}

// ============================================================================
// Per-shard tier construction. Decides the tier-split heuristic once per
// shard (it depends only on the chip max_reg distribution, which is shard-
// static) and uploads the per-tier ChunkStaticC arrays. The per-round
// launcher just builds dispatch tables on top of these.
// ============================================================================

/// Tier-split threshold and minority-ratio heuristic — see
/// `evaluate_zerocheck`'s old in-line decision for the motivation. Tier-split
/// only when the high-`max_reg` chunks are a small minority of all
/// Sequential chunks, otherwise the launch fragmentation cost outweighs the
/// per-thread footprint win.
const TIER_SPLIT_MAX_REG: u16 = 256;

/// Per-chip total GKR width (`main_width + prep_width`) above which we use
/// the dedicated `zerocheck_gkr_sweep` kernel (warp-per-row, lane-strided
/// columns) instead of the inline carrier-chunk loop. Narrow chips below
/// the threshold keep their inline GKR for L1 locality with constraint
/// reads; wide chips need column parallelism to scale.
///
/// Measured on RTX 5090: at 32 the kernel hand-off cost out-weighs the
/// column-parallel win until widths reach ~hundreds; 128 keeps the current
/// SP1 chip set (max width ~70) on the inline path while still routing
/// future regime-2 chips (widths 100-10k) through the decoupled kernel.
pub(crate) const WIDE_GKR_THRESHOLD: u32 = 256;

/// True iff this chip's GKR work should run in the dedicated decoupled
/// kernel. Stays false for typical SP1 chips today; flips to true for the
/// regime-2 case of chips with widths in the hundreds-to-thousands.
fn chip_uses_decoupled_gkr(main_width: u32, prep_width: u32) -> bool {
    main_width + prep_width > WIDE_GKR_THRESHOLD
}

fn build_seq_tiers(
    compiled: &[CompiledChipDevice],
    chip_alpha_offset: &[u32],
    scope: &TaskScope,
) -> [SeqTierStatic; 2] {
    let mut tier1_candidate_count = 0usize;
    let mut total_seq_count = 0usize;
    for chip in compiled.iter() {
        for chunk in chip.chunks.iter() {
            if matches!(chunk.kind, ChunkKind::Sequential) {
                total_seq_count += 1;
                if chunk.max_reg > TIER_SPLIT_MAX_REG {
                    tier1_candidate_count += 1;
                }
            }
        }
    }
    let do_tier_split = total_seq_count > 0
        && tier1_candidate_count > 0
        && tier1_candidate_count * 10 <= total_seq_count;

    let mut tiers: [SeqTierStatic; 2] = std::array::from_fn(|_| SeqTierStatic {
        static_host: Vec::new(),
        chip_indices: Vec::new(),
        max_reg: 0,
        static_buf: None,
    });

    for chip in compiled.iter() {
        let chip_idx = chip.chip_idx;
        // Decoupled-GKR chips have their inline widths zeroed so the
        // sequential kernel skips the in-line column sweep (the decoupled
        // kernel handles them).
        let decoupled = chip_uses_decoupled_gkr(chip.main_width, chip.prep_width);
        for chunk in chip.chunks.iter() {
            if !matches!(chunk.kind, ChunkKind::Sequential) {
                continue;
            }
            let tier: usize =
                if do_tier_split && chunk.max_reg > TIER_SPLIT_MAX_REG { 1 } else { 0 };
            tiers[tier].max_reg = tiers[tier].max_reg.max(chunk.max_reg);
            tiers[tier].chip_indices.push(chip_idx);
            tiers[tier].static_host.push(ChunkStaticC {
                instrs: chunk.instrs,
                leaves: chunk.leaves,
                consts: chunk.consts,
                publics: chunk.publics,
                assert_regs: chunk.assert_regs,
                assert_alphas: chunk.assert_alphas,
                n_instrs: chunk.n_instrs,
                n_asserts: chunk.n_asserts,
                chip_idx,
                gkr_main_width: if decoupled { 0 } else { chunk.gkr_main_width },
                gkr_prep_width: if decoupled { 0 } else { chunk.gkr_prep_width },
                chip_alpha_offset: chip_alpha_offset[chip_idx as usize],
            });
        }
    }

    for tier in tiers.iter_mut() {
        if !tier.static_host.is_empty() {
            tier.static_buf =
                Some(DeviceBuffer::from_host_slice(&tier.static_host, scope).unwrap().into_inner());
        }
    }
    tiers
}

/// Refill a cached device buffer in place from a host slice, growing the
/// allocation only when capacity is insufficient. Returns a reference to
/// the (now-refilled) buffer.
fn refill_buffer<'a, T: Copy + DeviceCopy>(
    cache: &'a mut Option<Buffer<T, TaskScope>>,
    host_data: &[T],
    scope: &TaskScope,
) -> &'a Buffer<T, TaskScope> {
    let needed = host_data.len().max(1);
    if cache.as_ref().is_none_or(|b| b.capacity() < needed) {
        *cache = Some(Buffer::with_capacity_in(needed, scope.clone()));
    }
    let buf = cache.as_mut().unwrap();
    // SAFETY: set_len(0) shrinks the buffer's effective length to zero before
    // we refill via extend_from_host_slice. Shrinking len is always safe (no
    // new bytes claimed); the previous bytes are not dropped, but T: Copy so
    // there's nothing to drop.
    unsafe {
        buf.set_len(0);
    }
    buf.extend_from_host_slice(host_data).unwrap();
    cache.as_ref().unwrap()
}

/// Pick the `zerocheck_pad_adj` template that covers a tier's worst-case
/// register footprint. Mirrors the `fused_sequential_kernel_for` ladder.
fn pad_adj_kernel_for(max_reg_in_tier: u16) -> KernelPtr {
    unsafe {
        if max_reg_in_tier <= 32 {
            zerocheck_pad_adj_32_kernel()
        } else if max_reg_in_tier <= 64 {
            zerocheck_pad_adj_64_kernel()
        } else if max_reg_in_tier <= 128 {
            zerocheck_pad_adj_128_kernel()
        } else if max_reg_in_tier <= 256 {
            zerocheck_pad_adj_256_kernel()
        } else if max_reg_in_tier <= 512 {
            zerocheck_pad_adj_512_kernel()
        } else {
            zerocheck_pad_adj_1024_kernel()
        }
    }
}

/// Compute the per-chip `padded_row_adjustment` on device: run the bytecode
/// interpreter at the all-zero trace for each chunk, sum asserts, then sum
/// per chip on the host (`chip_indices` tells us which chip each tier slot
/// belongs to).
///
/// Replaces the CPU `chip.air.eval` loop that used to run at shard init —
/// the device already has the bytecode and the alpha powers it needs.
/// ColumnTile chunks contribute exactly zero at the zero trace (every term
/// is `coeff · 0`), so summing only Sequential chunks is exact.
fn compute_padded_row_adjustment(
    n_chips: usize,
    seq_tiers: &[SeqTierStatic; 2],
    public_values: &Buffer<Felt, TaskScope>,
    powers_of_alpha: &Buffer<Ext, TaskScope>,
    scope: &TaskScope,
) -> Vec<Ext> {
    let mut padded_row_adjustment = vec![Ext::zero(); n_chips];
    const PAD_ADJ_BLOCK_SIZE: u32 = 64;
    for tier in seq_tiers.iter() {
        let n_chunks = tier.static_host.len();
        if n_chunks == 0 {
            continue;
        }
        let static_buf = tier.static_buf.as_ref().unwrap();
        let mut output: Tensor<Ext, TaskScope> = Tensor::with_sizes_in([n_chunks], scope.clone());
        unsafe {
            output.assume_init();
        }
        let n_blocks = (n_chunks as u32).div_ceil(PAD_ADJ_BLOCK_SIZE);
        unsafe {
            let args = args!(
                static_buf.as_ptr(),
                (n_chunks as u32),
                public_values.as_ptr(),
                powers_of_alpha.as_ptr(),
                output.as_mut_ptr()
            );
            scope
                .launch_kernel(
                    pad_adj_kernel_for(tier.max_reg),
                    (n_blocks, 1u32, 1u32),
                    (PAD_ADJ_BLOCK_SIZE, 1u32, 1u32),
                    &args,
                    0,
                )
                .unwrap();
        }
        let per_chunk: Vec<Ext> = unsafe { output.into_buffer().copy_into_host_vec() };
        for (i, &chip_idx) in tier.chip_indices.iter().enumerate() {
            padded_row_adjustment[chip_idx as usize] += per_chunk[i];
        }
    }
    padded_row_adjustment
}

/// Compute the per-chip main/preprocessed trace pointers within the jagged
/// dense buffer, using the jagged structure's `start_indices` and
/// `column_heights` (in pair units) as the source of truth:
///   main_ptr = startIndices[total_prep_cols + has_prep_padding + main_idx] << 1
///
/// The dense_offset values from `update_offset` (used by JaggedTraceMle's
/// table indices after a fold) silently drift from the actual jagged layout
/// when fold padding introduces extra elements at column ends — using
/// start_indices avoids that whole class of bugs.
///
/// Returns (main_ptrs, preprocessed_ptrs, heights), all in element units of
/// the underlying buffer type (Felt before round 0, Ext after).
fn compute_chip_offsets<A, K: Field>(
    data: &JaggedTraceMle<K, TaskScope>,
    chips: &BTreeSet<Chip<Felt, A>>,
) -> (Vec<u64>, Vec<u64>, Vec<u32>)
where
    A: MachineAir<Felt>,
{
    let column_heights = &data.0.column_heights;
    // start_indices in pair units derived from column_heights (cumulative).
    let mut starts: Vec<u64> = Vec::with_capacity(column_heights.len() + 1);
    starts.push(0);
    let mut acc: u64 = 0;
    for &h in column_heights.iter() {
        acc += h as u64;
        starts.push(acc);
    }

    let total_prep_widths: usize = chips.iter().map(|c| c.preprocessed_width()).sum();
    // Match v1's kernel convention: always assume a single prep-padding
    // column sits between prep cols and main cols. v1's evaluate_zerocheck
    // hardcodes `total_num_preprocessed_column + 1 + main_idx` for the same
    // reason. In practice padded prep is always rounded up so this column
    // exists.
    let main_section_start_col: usize = total_prep_widths + 1;

    let mut prep_ptrs = Vec::with_capacity(chips.len());
    let mut main_ptrs = Vec::with_capacity(chips.len());
    let mut heights = Vec::with_capacity(chips.len());

    let mut cum_prep: usize = 0;
    let mut cum_main: usize = 0;
    for chip in chips.iter() {
        let prep_w = chip.preprocessed_width();
        let main_w = chip.width();

        let prep_col_idx = cum_prep;
        let main_col_idx = main_section_start_col + cum_main;

        let prep_ptr = if prep_w > 0 { starts[prep_col_idx] * 2 } else { 0 };
        let main_ptr = if main_w > 0 { starts[main_col_idx] * 2 } else { 0 };

        // Column stride in element units. Prefer main if present (chip has
        // main cols), else prep. Chips with neither shouldn't reach here.
        let height = if main_w > 0 {
            column_heights[main_col_idx] * 2
        } else if prep_w > 0 {
            column_heights[prep_col_idx] * 2
        } else {
            0
        };

        prep_ptrs.push(prep_ptr);
        main_ptrs.push(main_ptr);
        heights.push(height);

        cum_prep += prep_w;
        cum_main += main_w;
    }

    (main_ptrs, prep_ptrs, heights)
}

// ============================================================================
// Per-round kernel launcher.
// ============================================================================

pub(crate) fn evaluate_zerocheck<'b, K: Field>(
    poly: &mut ZeroCheckJaggedPoly<'b, K>,
) -> UnivariatePolynomial<Ext>
where
    TaskScope: EvalKernels<K>,
{
    let backend = poly.data.backend();
    // Three evaluation points per univariate round (degree-2 polynomial
    // recovered by Lagrange interpolation downstream).
    const NUM_EVAL_POINT: usize = 3;
    // Cap on grid x-dim for the ColumnTile fallback. Beyond this, blocks
    // oversubscribe SMs and the per-block reduce overhead dominates.
    const MAX_GRID: u32 = 4096;
    // Block size per tier, keyed off the tier's worst-case `max_reg`: above
    // 128 the per-thread `regs[]` array crosses into a bigger MAX_REGS
    // template and we need a smaller block so enough warps still fit per SM
    // for latency hiding.
    const BLOCK_SIZE_LOW_REG: u32 = 256;
    const BLOCK_SIZE_HIGH_REG: u32 = 64;
    // Each thread handles this many rows from its tile (matches the old
    // grid-stride loop's `GRID_STRIDE_ROWS_PER_THREAD` so the reduce
    // overhead is amortised the same way). Tile size = block_size * this.
    const ROWS_PER_THREAD: u32 = 4;

    let (rest, last) = poly.zeta.split_at(poly.zeta.dimension() - 1);
    let last = *last[0];
    let rest_point = DevicePoint::from_host(&rest, backend).unwrap();
    let partial_lagrange = rest_point.partial_lagrange();
    let rest_point_dim = rest.dimension() as u32;

    let trace_ptr = poly.data.as_ref().dense_data.dense.as_ptr();

    let block_size_for = |tier: usize| -> u32 {
        if poly.seq_tiers[tier].max_reg > 128 {
            BLOCK_SIZE_HIGH_REG
        } else {
            BLOCK_SIZE_LOW_REG
        }
    };

    // ---- Build per-round chip layouts (one entry per active chip) ----
    //
    // The kernel reads `chip_layouts[chunk_static.chip_idx]` to get the
    // current trace pointers + height. Indexed by the shard-relative
    // `chip_idx` ∈ 0..n_active_chips. Empty chips still get a slot (with
    // zeroed height), but the dispatch builder below emits no entries for
    // them, so the kernel never reads those slots.
    let chip_layouts: Vec<ChipLayoutC> = (0..poly.compiled.len())
        .map(|i| ChipLayoutC {
            main_ptr: poly.chip_main_ptrs[i],
            preprocessed_ptr: poly.chip_preprocessed_ptrs[i],
            height: poly.chip_heights[i],
            _pad: 0,
        })
        .collect();
    // Reuse the cached chip_layouts buffer; refill in place (grow-only).
    let chip_layouts_ptr =
        refill_buffer(&mut poly.cached_chip_layouts_buf, &chip_layouts, backend).as_ptr();

    // ---- Walk active chips for ColumnTile fallback launches ----
    //
    // The Sequential dispatch table is built off `poly.seq_tiers` below.
    // Geq inputs all live on device — built at shard init in
    // `initialize_zerocheck_poly`, mutated in place by
    // `zerocheck_fix_geq_state` each round — so no per-round host iteration.
    let mut ct_launches: Vec<(u32, &ChunkDeviceBufs, u64, u64, u32, u32)> = Vec::new();
    for chip in poly.compiled.iter() {
        let chip_idx = chip.chip_idx;
        let row_count = poly.chip_heights[chip_idx as usize] / 2;
        if row_count == 0 {
            continue;
        }
        let main_ptr = poly.chip_main_ptrs[chip_idx as usize];
        let preprocessed_ptr = poly.chip_preprocessed_ptrs[chip_idx as usize];
        let height = poly.chip_heights[chip_idx as usize];

        for chunk in chip.chunks.iter() {
            if let ChunkKind::ColumnTile = chunk.kind {
                ct_launches.push((chip_idx, chunk, preprocessed_ptr, main_ptr, height, row_count));
            }
        }
    }

    // ---- Per-tier dispatch tables ----
    //
    // For each Sequential chunk in the tier, emit `ceil(row_count / tile)`
    // BlockDispatch entries. The kernel reads one entry per block and
    // strides through `n_rows` rows of `chunk_id`.
    let mut dispatch_tiers: [Vec<BlockDispatchC>; 2] = [Vec::new(), Vec::new()];
    for (t, tier) in poly.seq_tiers.iter().enumerate() {
        let tile = block_size_for(t) * ROWS_PER_THREAD;
        for (chunk_idx_in_tier, &chip_idx) in tier.chip_indices.iter().enumerate() {
            let row_count = poly.chip_heights[chip_idx as usize] / 2;
            if row_count == 0 {
                continue;
            }
            let mut row_offset = 0u32;
            while row_offset < row_count {
                let n_rows = (row_count - row_offset).min(tile);
                dispatch_tiers[t].push(BlockDispatchC {
                    chunk_id: chunk_idx_in_tier as u32,
                    row_offset,
                    n_rows,
                });
                row_offset += tile;
            }
        }
    }

    // ---- GKR dispatch table ----
    //
    // One block per (active chip, row-tile). The chip's `chip_idx` is
    // packed into `BlockDispatchC.chunk_id` (the GKR kernel reuses the
    // same descriptor struct, just with different field semantics).
    // Block size for GKR is fixed (256, 8 warps); tile = block_size *
    // ROWS_PER_THREAD matches the sequential pattern.
    const GKR_BLOCK_SIZE: u32 = 256;
    let gkr_tile: u32 = GKR_BLOCK_SIZE * ROWS_PER_THREAD;
    let mut gkr_dispatch: Vec<BlockDispatchC> = Vec::new();
    for &chip_idx in poly.gkr_active_chips.iter() {
        let row_count = poly.chip_heights[chip_idx as usize] / 2;
        if row_count == 0 {
            continue;
        }
        let mut row_offset = 0u32;
        while row_offset < row_count {
            let n_rows = (row_count - row_offset).min(gkr_tile);
            gkr_dispatch.push(BlockDispatchC { chunk_id: chip_idx, row_offset, n_rows });
            row_offset += gkr_tile;
        }
    }

    // ---- Slot allocation in the shared output ----
    let mut tier_slot: [usize; 2] = [0, 0];
    let mut total_slots: usize = 0;
    for t in 0..2 {
        tier_slot[t] = total_slots;
        total_slots += dispatch_tiers[t].len() * NUM_EVAL_POINT;
    }
    let mut ct_slots: Vec<(usize, u32)> = Vec::with_capacity(ct_launches.len());
    let ct_block_size: u32 = 128; // unchanged for ColumnTile fallback
    for &(_, chunk, _, _, _, row_count) in &ct_launches {
        let total = chunk.n_terms as u64 * row_count as u64;
        let n_blocks = if total == 0 {
            0
        } else {
            total.div_ceil(ct_block_size as u64).min(MAX_GRID as u64).max(1) as u32
        };
        ct_slots.push((total_slots, n_blocks));
        total_slots += (n_blocks as usize) * NUM_EVAL_POINT;
    }
    // Per-chip geq correction slots: one (chip, eval_point) per active geq
    // chip, each holding the already-negated `λ · pad_adj · S(e)` so the
    // host aggregation pass below adds them straight into totals.
    let geq_slot = total_slots;
    total_slots += poly.n_geq_chips * NUM_EVAL_POINT;
    // GKR sweep slots: one (block, eval_point) per GKR dispatch entry.
    let gkr_slot = total_slots;
    total_slots += gkr_dispatch.len() * NUM_EVAL_POINT;

    let mut shared_output: Tensor<Ext, TaskScope> =
        Tensor::with_sizes_in([total_slots.max(1)], backend.clone());
    unsafe {
        shared_output.assume_init();
    }
    let shared_output_ptr = shared_output.as_mut_ptr();

    // ---- Launch one fused kernel per non-empty tier ----
    //
    // Per-tier dispatch buffers are pooled in `poly.cached_seq_dispatch`
    // (grow-only) so we don't pay a CUDA malloc per round per tier.
    for t in 0..2 {
        if dispatch_tiers[t].is_empty() {
            continue;
        }
        let bs = block_size_for(t);
        let dispatch_ptr =
            refill_buffer(&mut poly.cached_seq_dispatch[t], &dispatch_tiers[t], backend).as_ptr();
        let static_ptr = poly.seq_tiers[t].static_buf.as_ref().unwrap().as_ptr();
        let max_reg = poly.seq_tiers[t].max_reg;
        let out_ptr = unsafe { shared_output_ptr.add(tier_slot[t]) };
        let shmem_bytes = (bs as usize / 32).max(1) * std::mem::size_of::<Ext>();
        unsafe {
            let args = args!(
                dispatch_ptr,
                static_ptr,
                chip_layouts_ptr,
                trace_ptr,
                poly.public_values.as_ptr(),
                poly.powers_of_alpha.as_ptr(),
                partial_lagrange.as_ptr(),
                poly.powers_of_lambda.as_ptr(),
                poly.gkr_powers.as_ptr(),
                rest_point_dim,
                out_ptr
            );
            backend
                .launch_kernel(
                    <TaskScope as EvalKernels<K>>::fused_sequential_kernel_for(max_reg),
                    (dispatch_tiers[t].len() as u32, 1, 3),
                    (bs, 1, 1),
                    &args,
                    shmem_bytes,
                )
                .unwrap();
        }
    }

    // Launch any remaining ColumnTile chunks individually (typically zero
    // for current SP1 workloads).
    for (i, &(chip_idx, chunk, preprocessed_ptr, main_ptr, height, row_count)) in
        ct_launches.iter().enumerate()
    {
        let (slot, n_blocks) = ct_slots[i];
        if n_blocks == 0 {
            continue;
        }
        let out_slot = unsafe { shared_output_ptr.add(slot) };
        launch_chunk_into::<K>(
            backend,
            chunk,
            trace_ptr,
            preprocessed_ptr,
            main_ptr,
            height,
            &poly.public_values,
            &poly.powers_of_alpha,
            poly.chip_alpha_offset[chip_idx as usize],
            partial_lagrange.as_ptr(),
            &poly.powers_of_lambda,
            chip_idx,
            rest_point_dim,
            0,
            row_count,
            n_blocks,
            ct_block_size,
            out_slot,
        );
    }

    // Launch the per-chip geq corrections kernel — one block per active geq
    // chip, all inputs already on device (see `chip_geq_state_dev`,
    // `chip_pad_adj_dev`, `geq_chip_indices_dev`, `chip_layouts_buf`).
    if poly.n_geq_chips > 0 {
        const GEQ_BLOCK_SIZE: u32 = 256;
        let geq_indices = poly.geq_chip_indices_dev.as_ref().unwrap();
        let out_ptr = unsafe { shared_output_ptr.add(geq_slot) };
        let shmem_bytes = (GEQ_BLOCK_SIZE as usize / 32) * std::mem::size_of::<Ext>();
        unsafe {
            let args = args!(
                geq_indices.as_ptr(),
                (poly.n_geq_chips as u32),
                poly.chip_geq_state_dev.as_ptr(),
                poly.chip_pad_adj_dev.as_ptr(),
                poly.powers_of_lambda.as_ptr(),
                chip_layouts_ptr,
                partial_lagrange.as_ptr(),
                rest_point_dim,
                out_ptr
            );
            backend
                .launch_kernel(
                    zerocheck_geq_corrections_kernel(),
                    (poly.n_geq_chips as u32, 1, 1),
                    (GEQ_BLOCK_SIZE, 1, 1),
                    &args,
                    shmem_bytes,
                )
                .unwrap();
        }
    }

    // ---- GKR column sweep ----
    //
    // Replaces the carrier-chunk piggyback that used to live inside the
    // sequential kernel. One block per (chip, row-tile); the kernel uses
    // warp-per-row + lane-strided column reduction so chips with widths in
    // the thousands parallelise across the warp's lanes instead of running
    // a O(width) column loop in a single thread.
    if !gkr_dispatch.is_empty() {
        let gkr_ptr = refill_buffer(&mut poly.cached_gkr_dispatch, &gkr_dispatch, backend).as_ptr();
        let out_ptr = unsafe { shared_output_ptr.add(gkr_slot) };
        let shmem_bytes = (GKR_BLOCK_SIZE as usize / 32) * std::mem::size_of::<Ext>();
        unsafe {
            let args = args!(
                gkr_ptr,
                chip_layouts_ptr,
                poly.chip_gkr_info_dev.as_ptr(),
                trace_ptr,
                poly.gkr_powers.as_ptr(),
                partial_lagrange.as_ptr(),
                poly.powers_of_lambda.as_ptr(),
                rest_point_dim,
                out_ptr
            );
            backend
                .launch_kernel(
                    <TaskScope as EvalKernels<K>>::gkr_sweep_kernel(),
                    (gkr_dispatch.len() as u32, 1, 3),
                    (GKR_BLOCK_SIZE, 1, 1),
                    &args,
                    shmem_bytes,
                )
                .unwrap();
        }
    }

    // ---- Device-side aggregation ----
    //
    // Every producer wrote `[block][e]` triples into `shared_output`. The
    // host used to download the whole buffer and sum it per eval point;
    // instead we launch a single-block reduction kernel that emits the 3
    // totals directly and download only those. Saves O(total_slots) host
    // work + O(total_slots) PCIe per round (at scale that's MBs per round
    // → KBs).
    //
    // `total_slots` is guaranteed a multiple of 3 (every slot range above
    // is `n * NUM_EVAL_POINT`).
    let mut totals_buf: Tensor<Ext, TaskScope> =
        Tensor::with_sizes_in([NUM_EVAL_POINT], backend.clone());
    unsafe {
        totals_buf.assume_init();
    }
    {
        const AGG_BLOCK_SIZE: u32 = 256;
        let shmem_bytes = (AGG_BLOCK_SIZE as usize / 32) * std::mem::size_of::<Ext>();
        unsafe {
            let args = args!(
                shared_output_ptr as *const Ext,
                (total_slots as u32),
                totals_buf.as_mut_ptr()
            );
            backend
                .launch_kernel(
                    zerocheck_aggregate_partials_kernel(),
                    (1u32, 1u32, 1u32),
                    (AGG_BLOCK_SIZE, 1u32, 1u32),
                    &args,
                    shmem_bytes,
                )
                .unwrap();
        }
    }

    // ---- Single host sync + copy of 3 totals ----
    let totals_vec: Vec<Ext> = unsafe { totals_buf.into_buffer().copy_into_host_vec() };
    let totals: [Ext; NUM_EVAL_POINT] = [totals_vec[0], totals_vec[1], totals_vec[2]];
    // `shared_output` is no longer needed; drop it after the sync so the
    // device allocation can be freed.
    drop(shared_output);

    // Apply last_var_eq and eq_adjustment (mirror v1's evaluate_zerocheck).
    let mut xs =
        vec![Ext::from_canonical_u32(0), Ext::from_canonical_u32(2), Ext::from_canonical_u32(4)];
    let mut ys: Vec<Ext> = xs
        .iter()
        .zip(totals.iter())
        .map(|(&x, &t)| {
            let last_var_eq = (Ext::one() - x) * (Ext::one() - last) + x * last;
            t * last_var_eq * poly.eq_adjustment
        })
        .collect();

    xs.push(Ext::from_canonical_u32(1));
    ys.push(poly.claim - ys[0]);

    xs.push((last - Ext::one()) / (last + last - Ext::one()));
    ys.push(Ext::zero());

    interpolate_univariate_polynomial(&xs, &ys)
}

/// Launch a chunk against a caller-provided device output pointer.
/// All launches in a round write into one shared buffer; the caller does a
/// single sync + copy_into_host at the end.
#[allow(clippy::too_many_arguments)]
fn launch_chunk_into<K: Field>(
    scope: &TaskScope,
    chunk: &ChunkDeviceBufs,
    trace_ptr: *const K,
    preprocessed_ptr: u64,
    main_ptr: u64,
    height: u32,
    public_values: &Buffer<Felt, TaskScope>,
    powers_of_alpha: &Buffer<Ext, TaskScope>,
    chip_alpha_offset: u32,
    partial_lagrange_ptr: *const Ext,
    powers_of_lambda: &Buffer<Ext, TaskScope>,
    chip_idx: u32,
    rest_point_dim: u32,
    row_start: u32,
    row_count: u32,
    n_blocks: u32,
    block_size: u32,
    output_ptr: *mut Ext,
) where
    TaskScope: EvalKernels<K>,
{
    let shmem_bytes = (block_size as usize / 32) * std::mem::size_of::<Ext>();
    match chunk.kind {
        // Sequential chunks are dispatched through the fused kernel
        // (`evaluate_zerocheck`); `launch_chunk_into` only ever sees ColumnTile.
        ChunkKind::Sequential => {
            unreachable!("Sequential chunks go through the fused kernel, not launch_chunk_into")
        }
        ChunkKind::ColumnTile => unsafe {
            // ColumnTile chunks store chip-relative `alpha_idx`; shift the
            // `powers_of_alpha` base by the per-chip offset.
            let powers_of_alpha_shifted = powers_of_alpha.as_ptr().add(chip_alpha_offset as usize);
            let args = args!(
                chunk.terms,
                chunk.n_terms,
                chunk.leaves,
                chunk.consts,
                chunk.publics,
                trace_ptr,
                preprocessed_ptr,
                main_ptr,
                height,
                public_values.as_ptr(),
                powers_of_alpha_shifted,
                partial_lagrange_ptr,
                powers_of_lambda.as_ptr(),
                chip_idx,
                rest_point_dim,
                row_start,
                row_count,
                output_ptr
            );
            scope
                .launch_kernel(
                    <TaskScope as EvalKernels<K>>::column_tile_kernel(),
                    (n_blocks, 1, 1),
                    (block_size, 1, 1),
                    &args,
                    shmem_bytes,
                )
                .unwrap();
        },
    }
}

// ============================================================================
// Fix-last-variable: fold trace data, update eq_adjustment.
// ============================================================================

pub(crate) fn zerocheck_fix_last_variable<'b, K: Field>(
    input: ZeroCheckJaggedPoly<'b, K>,
    point: Ext,
    claim: Ext,
) -> ZeroCheckJaggedPoly<'b, Ext>
where
    TaskScope: JaggedFixLastVariableKernel<K>,
    Ext: ExtensionField<K>,
{
    let (rest, last) = input.zeta.split_at(input.zeta.dimension() - 1);
    let last = *last[0];

    let new_data = evaluate_jagged_fix_last_variable(&input.data, point);
    let eq = (Ext::one() - last) * (Ext::one() - point) + last * point;
    let eq_adjustment = input.eq_adjustment * eq;

    // Mutate the device-resident per-chip geq state in place. One thread per
    // chip; pure ext arithmetic so we just hand it `point` as a kernel arg.
    let n_chips = input.compiled.len() as u32;
    if n_chips > 0 {
        const BS: u32 = 128;
        let n_blocks = n_chips.div_ceil(BS);
        let scope = new_data.dense().backend();
        unsafe {
            let args = args!(input.chip_geq_state_dev.as_ptr(), n_chips, point);
            scope
                .launch_kernel(
                    zerocheck_fix_geq_state_kernel(),
                    (n_blocks, 1, 1),
                    (BS, 1, 1),
                    &args,
                    0,
                )
                .unwrap();
        }
    }

    // After fold, the jagged layout may pad some columns (fold kernel adds 2
    // ext slots when `column_height_pairs % 4 != 0`). The `update_offset`
    // path used by `evaluate_jagged_fix_last_variable` to rewrite the
    // `dense_offset` ranges silently DRIFTS from the real column stride in
    // those cases — `update_offset` uses `poly_size.div_ceil(4) * 2`, the
    // actual stride uses `column_height_pairs.div_ceil(4) * 4`. Compute
    // ptrs/heights from the new jagged structure's `column_heights` instead.
    let column_heights = &new_data.0.column_heights;
    let mut starts: Vec<u64> = Vec::with_capacity(column_heights.len() + 1);
    starts.push(0);
    let mut acc: u64 = 0;
    for &h in column_heights.iter() {
        acc += h as u64;
        starts.push(acc);
    }

    let total_prep_widths: usize = input.compiled.iter().map(|c| c.prep_width as usize).sum();
    // See `compute_chip_offsets`: match v1's `+1` convention.
    let main_section_start_col: usize = total_prep_widths + 1;

    let mut chip_main_ptrs = Vec::with_capacity(input.compiled.len());
    let mut chip_preprocessed_ptrs = Vec::with_capacity(input.compiled.len());
    let mut chip_heights: Vec<u32> = Vec::with_capacity(input.compiled.len());

    let mut cum_prep: usize = 0;
    let mut cum_main: usize = 0;
    for c in input.compiled.iter() {
        let prep_w = c.prep_width as usize;
        let main_w = c.main_width as usize;
        let prep_col_idx = cum_prep;
        let main_col_idx = main_section_start_col + cum_main;
        let prep_ptr = if prep_w > 0 { starts[prep_col_idx] * 2 } else { 0 };
        let main_ptr = if main_w > 0 { starts[main_col_idx] * 2 } else { 0 };
        let height = if main_w > 0 {
            (column_heights[main_col_idx]) * 2
        } else if prep_w > 0 {
            (column_heights[prep_col_idx]) * 2
        } else {
            0
        };
        chip_preprocessed_ptrs.push(prep_ptr);
        chip_main_ptrs.push(main_ptr);
        chip_heights.push(height);
        cum_prep += prep_w;
        cum_main += main_w;
    }

    ZeroCheckJaggedPoly {
        data: Cow::Owned(new_data),
        compiled: input.compiled,
        machine_bytecode: input.machine_bytecode,
        eq_adjustment,
        zeta: rest,
        claim,
        padded_row_adjustment_host: input.padded_row_adjustment_host,
        public_values: input.public_values,
        powers_of_alpha: input.powers_of_alpha,
        gkr_powers: input.gkr_powers,
        powers_of_lambda: input.powers_of_lambda,
        chip_main_ptrs,
        chip_preprocessed_ptrs,
        chip_heights,
        chip_alpha_offset: input.chip_alpha_offset,
        seq_tiers: input.seq_tiers,
        chip_geq_state_dev: input.chip_geq_state_dev,
        chip_pad_adj_dev: input.chip_pad_adj_dev,
        geq_chip_indices_dev: input.geq_chip_indices_dev,
        n_geq_chips: input.n_geq_chips,
        chip_gkr_info_dev: input.chip_gkr_info_dev,
        gkr_active_chips: input.gkr_active_chips,
        cached_chip_layouts_buf: input.cached_chip_layouts_buf,
        cached_seq_dispatch: input.cached_seq_dispatch,
        cached_gkr_dispatch: input.cached_gkr_dispatch,
    }
}

// ============================================================================
// Outer driver — parallel to v1's `zerocheck`.
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub fn zerocheck<A, C>(
    chips: &BTreeSet<Chip<Felt, A>>,
    machine_bytecode: &Arc<MachineBytecode>,
    trace_mle: &JaggedTraceMle<Felt, TaskScope>,
    batching_challenge: Ext,
    gkr_opening_batch_randomness: Ext,
    logup_evaluations: &LogUpEvaluations<Ext>,
    public_values: Vec<Felt>,
    challenger: &mut C,
    max_log_row_count: u32,
) -> (ShardOpenedValues<Felt, Ext>, PartialSumcheckProof<Ext>)
where
    A: ZerocheckAir<Felt, Ext>,
    C: FieldChallenger<Felt>,
{
    let data_input_heights = &trace_mle.column_heights;
    let initial_heights = trace_mle
        .dense_data
        .main_table_index
        .values()
        .map(|trace_offset| trace_offset.poly_size as u32)
        .collect::<Vec<u32>>();

    let max_num_constraints =
        itertools::max(chips.iter().map(|chip| chip.num_constraints)).unwrap();
    let max_columns =
        itertools::max(chips.iter().map(|chip| chip.preprocessed_width() + chip.width())).unwrap();
    let total_preprocessed_columns = trace_mle.dense().preprocessed_cols;
    let mut powers_of_challenge =
        batching_challenge.powers().take(max_num_constraints).collect::<Vec<_>>();
    powers_of_challenge.reverse();
    let num_chips = chips.len();
    let debug_timing = std::env::var("SP1_GPU_ZEROCHECK_TIMING").is_ok();

    // `padded_row_adjustment` is now computed on device inside
    // `initialize_zerocheck_poly` (`zerocheck_pad_adj` kernel) — the host
    // CPU folder loop is gone.
    let t_setup = std::time::Instant::now();

    let gkr_powers =
        gkr_opening_batch_randomness.powers().skip(1).take(max_columns).collect::<Vec<_>>();

    let lambda: Ext = challenger.sample_ext_element();
    let powers_of_lambda =
        lambda.powers().take(num_chips).collect_vec().into_iter().rev().collect::<Vec<_>>();

    let mut claim = Ext::zero();
    let LogUpEvaluations { point: gkr_point, chip_openings } = logup_evaluations;
    for chip in chips.iter() {
        let ChipEvaluation {
            main_trace_evaluations: main_opening,
            preprocessed_trace_evaluations: prep_opening,
        } = chip_openings.get(chip.name()).unwrap();
        claim *= lambda;
        let addend = main_opening
            .evaluations()
            .as_slice()
            .iter()
            .chain(
                prep_opening
                    .as_ref()
                    .map_or_else(Vec::new, |mle| mle.evaluations().as_slice().to_vec())
                    .iter(),
            )
            .zip(gkr_powers.iter())
            .map(|(opening, power)| *opening * *power)
            .sum::<Ext>();
        claim += addend;
    }

    let t_pra_and_claim = t_setup.elapsed();

    // Select this shard's chips from the machine-wide bytecode (uploaded once
    // at prover construction). Cheap pointer-view clones — no device upload.
    let t_select = std::time::Instant::now();
    let compiled_dev: Vec<CompiledChipDevice> = chips
        .iter()
        .enumerate()
        .map(|(shard_idx, chip)| {
            let m = *machine_bytecode
                .chip_index
                .get(chip.name())
                .expect("shard chip not present in machine bytecode");
            let mut view = machine_bytecode.chips[m].clone();
            // Re-stamp to the shard-relative index used by the per-shard
            // arrays (`chip_heights`, `chip_alpha_offset`, …).
            view.chip_idx = shard_idx as u32;
            view
        })
        .collect();
    let t_select = t_select.elapsed();
    if debug_timing {
        tracing::info!(
            "zerocheck setup: num_chips={} pra+claim={:?} select={:?}",
            num_chips,
            t_pra_and_claim,
            t_select,
        );
    }

    let mut main_poly = initialize_zerocheck_poly(
        trace_mle,
        chips,
        compiled_dev,
        machine_bytecode.clone(),
        initial_heights.clone(),
        public_values,
        powers_of_challenge,
        gkr_powers,
        powers_of_lambda,
        gkr_point.clone(),
        claim,
    );

    let mut univariate_polys = vec![];
    let mut jagged_point: Point<Ext> = Point::from(vec![]);
    let t_eval_total = std::time::Instant::now();
    let mut total_fold = std::time::Duration::ZERO;
    let mut total_eval = std::time::Duration::ZERO;
    let mut total_chal = std::time::Duration::ZERO;
    let t = std::time::Instant::now();
    let mut result = evaluate_zerocheck(&mut main_poly);
    if debug_timing {
        total_eval += t.elapsed();
    }
    let t = std::time::Instant::now();
    let (mut point, mut next_claim) = challenger_update(&result, challenger);
    if debug_timing {
        total_chal += t.elapsed();
    }
    univariate_polys.push(result);
    jagged_point.add_dimension(point);
    let t = std::time::Instant::now();
    let mut next_poly = zerocheck_fix_last_variable(main_poly, point, next_claim);
    if debug_timing {
        total_fold += t.elapsed();
    }
    for _ in 0..max_log_row_count - 1 {
        let t = std::time::Instant::now();
        result = evaluate_zerocheck(&mut next_poly);
        if debug_timing {
            total_eval += t.elapsed();
        }
        let t = std::time::Instant::now();
        (point, next_claim) = challenger_update(&result, challenger);
        if debug_timing {
            total_chal += t.elapsed();
        }
        univariate_polys.push(result);
        jagged_point.add_dimension(point);
        let t = std::time::Instant::now();
        next_poly = zerocheck_fix_last_variable(next_poly, point, next_claim);
        if debug_timing {
            total_fold += t.elapsed();
        }
    }
    if debug_timing {
        tracing::info!(
            "zerocheck: total={:?} eval={:?} fold={:?} chal={:?}",
            t_eval_total.elapsed(),
            total_eval,
            total_fold,
            total_chal
        );
    }

    let final_jagged_data =
        unsafe { next_poly.data.as_ref().dense_data.dense.copy_into_host_vec() };

    let mut idx = 0;
    let mut individual_column_evals = vec![Ext::zero(); data_input_heights.len()];
    for i in 0..data_input_heights.len() {
        if data_input_heights[i] != 0 {
            individual_column_evals[i] = final_jagged_data[idx];
            idx += 4;
        }
    }

    let mut preprocessed_ptr = 0;
    let mut main_ptr = total_preprocessed_columns;
    let mut opened_values: BTreeMap<String, ChipOpenedValues<Felt, Ext>> = BTreeMap::new();
    challenger.observe(Felt::from_canonical_usize(chips.len()));
    for (i, chip) in chips.iter().enumerate() {
        let preprocessed_width = chip.preprocessed_width();
        let preprocessed = AirOpenedValues {
            local: individual_column_evals[preprocessed_ptr..preprocessed_ptr + preprocessed_width]
                .to_vec(),
        };
        challenger.observe_variable_length_extension_slice(&preprocessed.local);
        preprocessed_ptr += preprocessed_width;
        let width = chip.width();
        let main =
            AirOpenedValues { local: individual_column_evals[main_ptr..main_ptr + width].to_vec() };
        challenger.observe_variable_length_extension_slice(&main.local);
        main_ptr += width;
        opened_values.insert(
            chip.air.name().to_string(),
            ChipOpenedValues {
                preprocessed,
                main,
                degree: Point::from_usize(
                    initial_heights[i] as usize,
                    (max_log_row_count + 1) as usize,
                ),
            },
        );
    }

    let partial_sumcheck_proof = PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (jagged_point, next_claim),
    };
    let shard_open_values = ShardOpenedValues { chips: opened_values };
    (shard_open_values, partial_sumcheck_proof)
}
