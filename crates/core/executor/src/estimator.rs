//! Data that may be collected during execution and used to estimate trace area.

use std::ops::AddAssign;

use enum_map::EnumMap;

use crate::RiscvAirId;

/// Data accumulated during execution to estimate the core trace area used to prove the execution.
#[derive(Clone, Debug, Default)]
pub struct TraceAreaEstimator {
    /// Core shards, represented by the number of events per AIR.
    pub core_shards: Vec<EnumMap<RiscvAirId, u64>>,
    /// Deferred events, which are used to calculate trace area after execution has finished.
    pub deferred_events: EnumMap<RiscvAirId, u64>,
}

impl AddAssign for TraceAreaEstimator {
    fn add_assign(&mut self, rhs: Self) {
        let TraceAreaEstimator { core_shards, deferred_events } = self;
        core_shards.extend(rhs.core_shards);
        deferred_events
            .as_mut_array()
            .iter_mut()
            .zip(rhs.deferred_events.as_array())
            .for_each(|(l, r)| *l += r);
    }
}
