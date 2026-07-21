use crate::{
    cost_and_height_per_syscall, rv64im_costs, utils::trunc_32, RetainedEventsPreset, RiscvAirId,
    SyscallCode, BYTE_NUM_ROWS, RANGE_NUM_ROWS,
};
use enum_map::EnumMap;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env};

const MAX_SHARD_SIZE: usize = 1 << 24;

/// The trace area threshold for a shard.
pub const ELEMENT_THRESHOLD: u64 = (1 << 28) + (1 << 27);
/// The height threshold for a shard.
pub const HEIGHT_THRESHOLD: u64 = 1 << 22;
/// The maximum size of a minimal trace chunk in terms of memory entries.
///
/// 16,777,216 entries × 16 B/entry = 256 MiB per chunk. With
/// [`DEFAULT_TRACE_CHUNK_SLOTS`] slots in the SHM ring buffer, this caps the
/// trace-ring shared memory at ~5 × 256 MiB × 10/9 ≈ 1.43 GiB.
pub const MINIMAL_TRACE_CHUNK_THRESHOLD: u64 = 16_777_216;
/// The size of a minimal trace chunk used **for gas estimation**, in memory entries.
///
/// Gas estimation treats each trace chunk as a shard for memory-boundary accounting: the
/// `MemoryLocal`/`Global` row counts are keyed off `shard_start_clk`, which is reset to the chunk
/// start. The metered gas therefore depends on this chunking cadence (smaller chunks => more
/// boundaries => more re-counted "first read this shard" rows => higher gas).
///
/// For that reason it is intentionally decoupled from [`MINIMAL_TRACE_CHUNK_THRESHOLD`], which
/// exists purely to bound the executor's trace-ring memory and is free to change for perf reasons
/// (e.g. #2793 cut it 8x). This value is the cadence the gas estimate was calibrated against to
/// match v6.1.0 (see #2786) and must not be changed without re-validating gas against that
/// reference. 134,217,728 entries = 2 GiB / 16 B per entry = `1 << 27`.
pub const GAS_TRACE_CHUNK_THRESHOLD: u64 = 134_217_728;
/// The default number trace chunk slots
pub const DEFAULT_TRACE_CHUNK_SLOTS: usize = 5;
/// The default number of trace-chunk ring-buffer slots used **for gas estimation**.
///
/// Gas chunks are [`GAS_TRACE_CHUNK_THRESHOLD`]-sized (~2.2 GiB each via `trace_capacity`), 8× the
/// proving chunk, so the SHM ring is sized by `slots × ~2.2 GiB`. Gas estimation runs as a
/// standalone `EXECUTE_ONLY` task (not alongside proving), so it uses fewer slots than
/// [`DEFAULT_TRACE_CHUNK_SLOTS`] to cap that footprint — 2 slots keep executor↔gas double-buffering
/// at ~4.4 GiB instead of ~11 GiB. This only affects the gas path; proving is unaffected.
pub const DEFAULT_GAS_TRACE_CHUNK_SLOTS: usize = 2;
/// Default memory limit for SP1 programs, note this value has different semantics
/// on different implementation. For native executor, it is the limit on total
/// process memory(resident set size, or RSS) of this entire child process. For
/// portable executor, it is merely the limit on created memory entries. This
/// means the actual memory usage for portable executor will exceed this limit.
pub const DEFAULT_MEMORY_LIMIT: u64 = 24 * 1024 * 1024 * 1024;

/// The threshold that determines when to split the shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardingThreshold {
    /// The maximum number of elements in the trace.
    pub element_threshold: u64,
    /// The maximum number of rows for a single operation.
    pub height_threshold: u64,
}

/// Options for the core prover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SP1CoreOpts {
    /// The maximum size of a minimal trace chunk in terms of memory entries.
    pub minimal_trace_chunk_threshold: u64,
    /// The size of a minimal trace chunk used for gas estimation, in memory entries.
    ///
    /// Decoupled from [`Self::minimal_trace_chunk_threshold`] (which only bounds executor memory)
    /// because the metered gas depends on the chunking cadence. See [`GAS_TRACE_CHUNK_THRESHOLD`].
    pub gas_trace_chunk_threshold: u64,
    /// The number of slots in trace chunk ring buffer.
    pub trace_chunk_slots: usize,
    /// The number of trace-chunk ring-buffer slots used by the gas-estimation path.
    ///
    /// Kept smaller than [`Self::trace_chunk_slots`] because gas chunks are much larger
    /// ([`GAS_TRACE_CHUNK_THRESHOLD`]). See [`DEFAULT_GAS_TRACE_CHUNK_SLOTS`].
    pub gas_trace_chunk_slots: usize,
    /// The memory limit of SP1 program.
    pub memory_limit: u64,
    /// The size of a shard in terms of cycles. Used for estimating event counts when allocating records.
    pub shard_size: usize,
    /// The threshold that determines when to split the shard.
    pub sharding_threshold: ShardingThreshold,
    /// Preset collections of events to retain in a shard instead of deferring.
    pub retained_events_presets: HashSet<RetainedEventsPreset>,
    /// Use optimized `generate_dependencies` for global chip.
    pub global_dependencies_opt: bool,
    /// Recompute GKR trace
    pub recompute_gkr_trace: bool,
}

impl Default for SP1CoreOpts {
    fn default() -> Self {
        let minimal_trace_chunk_threshold = env::var("MINIMAL_TRACE_CHUNK_THRESHOLD").map_or_else(
            |_| MINIMAL_TRACE_CHUNK_THRESHOLD,
            |s| s.parse::<u64>().unwrap_or(MINIMAL_TRACE_CHUNK_THRESHOLD),
        );

        let gas_trace_chunk_threshold = env::var("GAS_TRACE_CHUNK_THRESHOLD").map_or_else(
            |_| GAS_TRACE_CHUNK_THRESHOLD,
            |s| s.parse::<u64>().unwrap_or(GAS_TRACE_CHUNK_THRESHOLD),
        );

        let trace_chunk_slots = env::var("TRACE_CHUNK_SLOTS").map_or_else(
            |_| DEFAULT_TRACE_CHUNK_SLOTS,
            |s| s.parse::<usize>().unwrap_or(DEFAULT_TRACE_CHUNK_SLOTS),
        );

        let gas_trace_chunk_slots = env::var("GAS_TRACE_CHUNK_SLOTS").map_or_else(
            |_| DEFAULT_GAS_TRACE_CHUNK_SLOTS,
            |s| s.parse::<usize>().unwrap_or(DEFAULT_GAS_TRACE_CHUNK_SLOTS),
        );

        let memory_limit = env::var("MEMORY_LIMIT").map_or_else(
            |_| DEFAULT_MEMORY_LIMIT,
            |s| s.parse::<u64>().unwrap_or(DEFAULT_MEMORY_LIMIT),
        );

        let shard_size = env::var("SHARD_SIZE")
            .map_or_else(|_| MAX_SHARD_SIZE, |s| s.parse::<usize>().unwrap_or(MAX_SHARD_SIZE));

        let element_threshold = env::var("ELEMENT_THRESHOLD")
            .map_or_else(|_| ELEMENT_THRESHOLD, |s| s.parse::<u64>().unwrap_or(ELEMENT_THRESHOLD));

        let height_threshold = env::var("HEIGHT_THRESHOLD")
            .map_or_else(|_| HEIGHT_THRESHOLD, |s| s.parse::<u64>().unwrap_or(HEIGHT_THRESHOLD));

        let sharding_threshold = ShardingThreshold { element_threshold, height_threshold };

        let mut retained_events_presets = HashSet::new();
        retained_events_presets.insert(RetainedEventsPreset::Bls12381Field);
        retained_events_presets.insert(RetainedEventsPreset::Bn254Field);
        retained_events_presets.insert(RetainedEventsPreset::Sha256);
        retained_events_presets.insert(RetainedEventsPreset::Poseidon2);
        retained_events_presets.insert(RetainedEventsPreset::U256Ops);

        Self {
            minimal_trace_chunk_threshold,
            gas_trace_chunk_threshold,
            trace_chunk_slots,
            gas_trace_chunk_slots,
            memory_limit,
            shard_size,
            sharding_threshold,
            retained_events_presets,
            global_dependencies_opt: false,
            recompute_gkr_trace: false,
        }
    }
}

/// Options for splitting deferred events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitOpts {
    /// The threshold for combining the memory and page prot init/finalize events in to the current
    /// shard in terms of the estimated trace area of the shard.
    pub pack_trace_threshold: u64,
    /// The threshold for combining the memory init/finalize events in to the current shard in
    /// terms of the number of memory init/finalize events.
    pub combine_memory_threshold: usize,
    /// The threshold for combining the page prot init/finalize events in to the current shard in
    /// terms of the number of page prot init/finalize events.
    pub combine_page_prot_threshold: usize,
    /// The threshold for syscall codes.
    pub syscall_threshold: EnumMap<SyscallCode, usize>,
    /// The threshold for memory events.
    pub memory: usize,
    /// The threshold for page prot events.
    pub page_prot: usize,
}

impl SplitOpts {
    /// Create a new [`SplitOpts`] with the given [`SP1CoreOpts`] and the program size.
    #[must_use]
    pub fn new(opts: &SP1CoreOpts, program_size: usize, page_protect_allowed: bool) -> Self {
        let costs = rv64im_costs();

        let mut available_trace_area = opts.sharding_threshold.element_threshold;
        let mut fixed_trace_area = 0;
        fixed_trace_area += program_size.next_multiple_of(32) * costs[&RiscvAirId::Program];
        fixed_trace_area += BYTE_NUM_ROWS as usize * costs[&RiscvAirId::Byte];
        fixed_trace_area += RANGE_NUM_ROWS as usize * costs[&RiscvAirId::Range];

        assert!(
            available_trace_area >= fixed_trace_area as u64,
            "SP1CoreOpts's element threshold is too low"
        );

        available_trace_area -= fixed_trace_area as u64;

        let max_height = opts.sharding_threshold.height_threshold;

        let syscall_threshold = EnumMap::from_fn(|syscall_code: SyscallCode| {
            if syscall_code.should_send() == 0 || syscall_code.as_air_id().is_none() {
                return 0;
            }

            let (cost_per_syscall, max_height_per_syscall) =
                cost_and_height_per_syscall(syscall_code, &costs, page_protect_allowed);
            let element_threshold = trunc_32(available_trace_area as usize / cost_per_syscall);
            let height_threshold = trunc_32(max_height as usize / max_height_per_syscall);

            element_threshold.min(height_threshold)
        });

        let cost_per_memory = costs[&RiscvAirId::MemoryGlobalInit] + costs[&RiscvAirId::Global];
        let memory = trunc_32(
            (available_trace_area as usize / cost_per_memory).min(max_height as usize) / 2,
        );
        let cost_per_page_prot =
            costs[&RiscvAirId::PageProtGlobalInit] + costs[&RiscvAirId::Global];
        let page_prot = trunc_32(
            (available_trace_area as usize / cost_per_page_prot).min(max_height as usize) / 2,
        );

        // Allocate `2/3` of the trace area to the usual trace area.
        let pack_trace_threshold = 2 * opts.sharding_threshold.element_threshold / 3;
        // Allocate `3/10` of the trace area to `MemoryGlobal` and `PageProtGlobal`.
        let mut combine_memory_threshold =
            trunc_32(3 * opts.sharding_threshold.element_threshold as usize / cost_per_memory / 40);
        let mut combine_page_prot_threshold = trunc_32(
            3 * opts.sharding_threshold.element_threshold as usize / cost_per_page_prot / 40,
        );

        // If page protection is off, use the `3/10` of the trace area for `MemoryGlobal` only.
        if !page_protect_allowed {
            combine_memory_threshold *= 2;
            combine_page_prot_threshold = 0;
        }

        Self {
            pack_trace_threshold,
            combine_memory_threshold,
            combine_page_prot_threshold,
            syscall_threshold,
            memory,
            page_prot,
        }
    }
}
