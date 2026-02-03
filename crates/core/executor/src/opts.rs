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
pub const MINIMAL_TRACE_CHUNK_THRESHOLD: u64 =
    2147483648 / std::mem::size_of::<sp1_jit::MemValue>() as u64;

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
    /// The size of a shard in terms of cycles. Used for estimating event counts when allocating records.
    pub shard_size: usize,
    /// The threshold that determines when to split the shard.
    pub sharding_threshold: ShardingThreshold,
    /// Preset collections of events to retain in a shard instead of deferring.
    pub retained_events_presets: HashSet<RetainedEventsPreset>,
    /// Use optimized `generate_dependencies` for global chip.
    pub global_dependencies_opt: bool,
}

impl Default for SP1CoreOpts {
    fn default() -> Self {
        let minimal_trace_chunk_threshold = env::var("MINIMAL_TRACE_CHUNK_THRESHOLD").map_or_else(
            |_| MINIMAL_TRACE_CHUNK_THRESHOLD,
            |s| s.parse::<u64>().unwrap_or(MINIMAL_TRACE_CHUNK_THRESHOLD),
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
            shard_size,
            sharding_threshold,
            retained_events_presets,
            global_dependencies_opt: false,
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
        assert!(!page_protect_allowed, "page protection is turned off");

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
            if syscall_code.should_send() == 0 {
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

        // Allocate `2/3` of the trace area to the usual trace area.
        let pack_trace_threshold = 2 * opts.sharding_threshold.element_threshold / 3;
        // Allocate `3/10` of the trace area to `MemoryGlobal`.
        let combine_memory_threshold =
            trunc_32(3 * opts.sharding_threshold.element_threshold as usize / cost_per_memory / 20);

        Self {
            pack_trace_threshold,
            combine_memory_threshold,
            combine_page_prot_threshold: 0,
            syscall_threshold,
            memory,
            page_prot: 0,
        }
    }
}
