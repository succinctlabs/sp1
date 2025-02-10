//! Data that may be collected during execution and used to estimate trace area.

use std::ops::AddAssign;

use enum_map::EnumMap;
use range_set_blaze::RangeSetBlaze;

use crate::RiscvAirId;

// TODO(tqn) rename this type
/// Data accumulated during execution to estimate the core trace area used to prove the execution.
#[derive(Clone, Debug, Default)]
pub struct TraceAreaEstimator {
    /// Core shards, represented by the number of events per AIR.
    pub core_shards: Vec<EnumMap<RiscvAirId, u64>>,
    /// Deferred events, which are used to calculate trace area after execution has finished.
    pub deferred_events: EnumMap<RiscvAirId, u64>,
    /// Keeps track of touched addresses to correctly count local memory events in precompiles.
    // TODO(tqn) the plan:
    // in mr/mw (and maybe rr/rw):
    // when not a precompile, set it. if it was previously unset, add one to the counter.
    // when a precompile, unset it and do nothing to the counter.
    // when this is set successfully (returned by .insert), increment the below counter
    pub current_touched_compressed_addresses: RangeSetBlaze<u32>,
    pub current_precompile_touched_compressed_addresses: RangeSetBlaze<u32>,
    /// More correct number of local memory events for the current shard.
    pub current_local_mem: usize,
}
