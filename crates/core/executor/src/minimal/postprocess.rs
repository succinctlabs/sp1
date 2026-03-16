use crate::events::MemoryInitializeFinalizeEvent;

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
