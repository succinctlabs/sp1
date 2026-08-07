/// Inspired from `events/precompiles/mod.rs`
use crate::{
    deserialize_hashmap_as_vec,
    events::{MemoryLocalEvent, PrecompileLocalMemory},
    serialize_hashmap_as_vec,
};
use hashbrown::HashMap;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sp1_hypercube::MachineRecord;

use crate::ExecutionRecord;

use super::PageProtLocalEvent;

/// A record of all the apc events for a specific apc id.
#[derive(Clone, Debug, Serialize, Deserialize, Default, deepsize2::DeepSizeOf)]
pub struct ApcEventsForId {
    /// The number of events.
    pub count: usize,
    /// The cumulative record of all events.
    pub record: ExecutionRecord,
}

/// A record of all the apc events.
#[derive(Clone, Debug, Serialize, Deserialize, Default, deepsize2::DeepSizeOf)]
pub struct ApcEvents {
    #[serde(serialize_with = "serialize_hashmap_as_vec")]
    #[serde(deserialize_with = "deserialize_hashmap_as_vec")]
    /// The apc events mapped by apc id.
    pub events: HashMap<usize, ApcEventsForId>,
}

impl ApcEvents {
    pub(crate) fn append(&mut self, other: &mut ApcEvents) {
        for (id, event) in other.events.iter_mut() {
            let entry = self.events.entry(*id).or_default();
            entry.count += event.count;
            entry.record.append(&mut event.record);
        }
    }

    #[inline]
    /// Add a precompile event for a given apc id.
    pub fn add_event(&mut self, apc_id: usize, mut event: ExecutionRecord) {
        let entry = self.events.entry(apc_id).or_default();
        entry.count += 1;
        entry.record.append(&mut event);
    }

    /// Checks if the precompile events are empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get the number of precompile events.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.values().map(|events| events.count).sum()
    }

    /// Get all the precompile events for a given apc id.
    #[inline]
    #[must_use]
    pub fn get_events(&self, apc_id: usize) -> Option<&ApcEventsForId> {
        self.events.get(&apc_id)
    }

    /// Get all the local events from all the precompile events.
    pub(crate) fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let mut iterators = Vec::new();

        for (_, events) in self.events.iter() {
            iterators.push(events.get_local_mem_events());
        }

        iterators.into_iter().flatten()
    }

    /// Get all the local page prot events from all the precompile events.
    pub(crate) fn get_local_page_prot_events(&self) -> impl Iterator<Item = &PageProtLocalEvent> {
        let mut iterators = Vec::new();

        for (_, events) in self.events.iter() {
            iterators.push(events.get_local_page_prot_events());
        }

        iterators.into_iter().flatten()
    }
}

impl PrecompileLocalMemory for ApcEventsForId {
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent> {
        self.record.get_local_mem_events().collect_vec().into_iter()
    }

    fn get_local_page_prot_events(&self) -> impl IntoIterator<Item = &PageProtLocalEvent> {
        self.record.get_local_page_prot_events().collect_vec().into_iter()
    }
}
