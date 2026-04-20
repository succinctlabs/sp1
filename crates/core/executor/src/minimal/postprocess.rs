use hashbrown::HashSet;

use crate::{
    events::{MemoryInitializeFinalizeEvent, MemoryRecord, PageProtInitializeFinalizeEvent},
    ExecutionMode, ExecutionRecord, MinimalExecutor,
};

use sp1_primitives::consts::DEFAULT_PAGE_PROT;

impl<M: ExecutionMode> MinimalExecutor<M> {
    /// Postprocess into an existing [`ExecutionRecord`],
    /// consisting of all the [`MemoryInitializeFinalizeEvent`]s.
    #[tracing::instrument(name = "emit globals", skip_all)]
    pub fn emit_globals(
        &self,
        record: &mut ExecutionRecord,
        final_registers: [MemoryRecord; 32],
        mut touched_addresses: HashSet<u64>,
        mut touched_pages: HashSet<u64>,
    ) {
        // Add all the finalize addresses to the touched addresses.
        touched_addresses.extend(self.program().memory_image.keys().copied());

        record.global_memory_initialize_events.extend(
            final_registers
                .iter()
                .enumerate()
                .filter(|(_, e)| e.timestamp != 0)
                .map(|(i, _)| MemoryInitializeFinalizeEvent::initialize(i as u64, 0)),
        );

        record.global_memory_finalize_events.extend(
            final_registers.iter().enumerate().filter(|(_, e)| e.timestamp != 0).map(
                |(i, entry)| {
                    MemoryInitializeFinalizeEvent::finalize(i as u64, entry.value, entry.timestamp)
                },
            ),
        );

        let hint_init_events: Vec<MemoryInitializeFinalizeEvent> = self
            .hints()
            .iter()
            .flat_map(|(addr, value)| chunked_memory_init_events(*addr, value))
            .collect::<Vec<_>>();
        let hint_addrs = hint_init_events.iter().map(|event| event.addr).collect::<HashSet<_>>();

        // Initialize the all the hints written during execution.
        record.global_memory_initialize_events.extend(hint_init_events);

        // Initialize the memory addresses that were touched during execution.
        // We don't initialize the memory addresses that were in the program image, since they were
        // initialized in the MemoryProgram chip.
        let memory_init_events = touched_addresses
            .iter()
            .filter(|addr| !self.program().memory_image.contains_key(*addr))
            .filter(|addr| !hint_addrs.contains(*addr))
            .map(|addr| MemoryInitializeFinalizeEvent::initialize(*addr, 0));
        record.global_memory_initialize_events.extend(memory_init_events);

        // Ensure all the hinted addresses are initialized.
        touched_addresses.extend(hint_addrs);

        // Finalize the memory addresses that were touched during execution.
        for addr in &touched_addresses {
            let entry = self.get_memory_value(*addr);

            record.global_memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize(
                *addr,
                entry.value,
                entry.clk,
            ));
        }

        if M::PAGE_PROTECTION_ENABLED {
            touched_pages.extend(self.program().page_prot_image.keys().copied());

            let page_prot_initialize_events = &mut record.global_page_prot_initialize_events;
            page_prot_initialize_events.reserve_exact(touched_pages.len());

            let page_prot_finalize_events = &mut record.global_page_prot_finalize_events;
            page_prot_finalize_events.reserve_exact(touched_pages.len());

            for page_idx in &touched_pages {
                let record = self.get_page_prot_record(*page_idx).unwrap();

                // Only push initialize event if the page prot idx is not in the initial page
                // prot image.
                if !self.program().page_prot_image.contains_key(page_idx) {
                    page_prot_initialize_events.push(PageProtInitializeFinalizeEvent::initialize(
                        *page_idx,
                        DEFAULT_PAGE_PROT,
                    ));
                }

                page_prot_finalize_events.push(PageProtInitializeFinalizeEvent {
                    page_idx: *page_idx,
                    page_prot: record.value,
                    timestamp: record.timestamp,
                });
            }
        } else {
            assert!(touched_pages.is_empty());
        }
    }

    /// Get set of addresses that were hinted.
    #[must_use]
    pub fn get_hint_event_addrs(&self) -> HashSet<u64> {
        let events = self
            .hints()
            .iter()
            .flat_map(|(addr, value)| chunked_memory_init_events(*addr, value))
            .collect::<Vec<_>>();
        let hint_event_addrs = events.iter().map(|event| event.addr).collect::<HashSet<_>>();

        hint_event_addrs
    }
}

/// Given some contiguous memory, create a series of initialize and finalize events.
///
/// The events are created in chunks of 8 bytes.
///
/// The last chunk is not guaranteed to be 8 bytes, so we need to handle that case by padding with
/// 0s.
#[must_use]
pub fn chunked_memory_init_events(start: u64, bytes: &[u8]) -> Vec<MemoryInitializeFinalizeEvent> {
    let chunks = bytes.chunks_exact(8);
    let num_chunks = chunks.len();
    let last = chunks.remainder();

    let mut output = Vec::with_capacity(num_chunks + 1);

    for (i, chunk) in chunks.enumerate() {
        let addr = start + i as u64 * 8;
        let value = u64::from_le_bytes(chunk.try_into().unwrap());
        output.push(MemoryInitializeFinalizeEvent::initialize(addr, value));
    }

    if !last.is_empty() {
        let addr = start + num_chunks as u64 * 8;
        let buf = {
            let mut buf = [0u8; 8];
            buf[..last.len()].copy_from_slice(last);
            buf
        };

        let value = u64::from_le_bytes(buf);
        output.push(MemoryInitializeFinalizeEvent::initialize(addr, value));
    }

    output
}
