//! Data that may be collected during execution and used to estimate trace area.

use enum_map::EnumMap;
use range_set_blaze::RangeSetBlaze;

use crate::RiscvAirId;

/// Data accumulated during execution to estimate the core trace area used to prove the execution.
#[derive(Clone, Debug, Default)]
pub struct RecordEstimator {
    /// Core shards, represented by the number of events per AIR.
    pub core_records: Vec<EnumMap<RiscvAirId, u64>>,
    /// For each precompile AIR, a list of estimated records in the form
    /// `(<number of precompile events>, <number of local memory events>)`.
    pub precompile_records: EnumMap<RiscvAirId, Vec<(u64, u64)>>,
    /// Number of memory global init events for the whole program.
    pub memory_global_init_events: u64,
    /// Number of memory global finalize events for the whole program.
    pub memory_global_finalize_events: u64,
    /// Addresses touched in this shard by the main executor.
    /// Used to calculate local memory events.
    pub current_touched_compressed_addresses: RangeSetBlaze<u32>,
    /// Addresses touched in this shard by the current precompile execution.
    /// Used to calculate local memory events.
    pub current_precompile_touched_compressed_addresses: RangeSetBlaze<u32>,
    /// More correct number of local memory events for the current shard.
    pub current_local_mem: usize,
}
