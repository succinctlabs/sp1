use crate::events::MemoryRecord;
use deepsize2::{Context, DeepSizeOf};
use serde::{Deserialize, Serialize};
use sp1_jit::MemValue;
use std::collections::HashMap;
use std::sync::Arc;

/// A self-contained, minimal record of one APC invocation — enough to re-execute the block and
/// regenerate its per-opcode events (the APC witness) in the chip, without materializing those
/// events during tracing. This is the "record-in-chip" capture: the executor skips emitting the
/// block's events and stores this instead; the APC chip replays from it.
///
/// The block's memory-read oracle is stored zero-copy: all invocations captured in one shard share
/// a single `Arc<[MemValue]>` (the whole shard read-oracle) and index into it via `read_offset` /
/// `read_len`. Copying the slice per invocation (there are millions on a real program) is what
/// blew memory up ~3x and OOM'd RSP; sharing the `Arc` is a refcount bump.
#[derive(Debug, Clone)]
pub struct ApcInvocation {
    /// Which APC this invocation runs.
    pub apc_id: usize,
    /// Register file at block entry: value AND previous-access timestamp.
    pub pre_registers: [MemoryRecord; 32],
    /// Program counter at block entry.
    pub pc_start: u64,
    /// Clock at block entry.
    pub clk_start: u64,
    /// Global clock at block entry.
    pub global_clk_start: u64,
    /// Shared shard read-oracle (one buffer per shard, refcount-shared across invocations).
    pub reads: Arc<[MemValue]>,
    /// This block's read slice within `reads`.
    pub read_offset: usize,
    pub read_len: usize,
    /// Number of original instructions in the block (how many cycles to re-execute).
    pub num_instructions: usize,
}

impl ApcInvocation {
    /// This block's memory-read oracle slice, in access order.
    #[must_use]
    pub fn mem_reads(&self) -> &[MemValue] {
        &self.reads[self.read_offset..self.read_offset + self.read_len]
    }
}

/// Serialization proxy: the shared `Arc`/offsets are an in-memory optimization, so on the wire an
/// invocation carries only its own block reads (identical bytes to the pre-optimization `Vec`
/// field). Deserialization gives each invocation its own single-block `Arc` (sharing only matters
/// in-process, where nothing serializes between capture and chip replay).
#[derive(Serialize, Deserialize)]
struct ApcInvocationSer {
    apc_id: usize,
    pre_registers: [MemoryRecord; 32],
    pc_start: u64,
    clk_start: u64,
    global_clk_start: u64,
    mem_reads: Vec<MemValue>,
    num_instructions: usize,
}

impl Serialize for ApcInvocation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ApcInvocationSer {
            apc_id: self.apc_id,
            pre_registers: self.pre_registers,
            pc_start: self.pc_start,
            clk_start: self.clk_start,
            global_clk_start: self.global_clk_start,
            mem_reads: self.mem_reads().to_vec(),
            num_instructions: self.num_instructions,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ApcInvocation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = ApcInvocationSer::deserialize(deserializer)?;
        let read_len = s.mem_reads.len();
        Ok(ApcInvocation {
            apc_id: s.apc_id,
            pre_registers: s.pre_registers,
            pc_start: s.pc_start,
            clk_start: s.clk_start,
            global_clk_start: s.global_clk_start,
            reads: Arc::from(s.mem_reads),
            read_offset: 0,
            read_len,
            num_instructions: s.num_instructions,
        })
    }
}

/// Per-`apc_id` store of the record-in-chip invocations — replaces PR2738's materialized
/// `ApcEvents`. The APC chip regenerates its trace by replaying these; an APC's row count is
/// simply its number of invocations. No carving / span cache (that was `ApcPartition`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApcInvocations {
    by_id: HashMap<usize, Vec<ApcInvocation>>,
}

impl ApcInvocations {
    /// Record one successful APC invocation.
    pub fn push(&mut self, inv: ApcInvocation) {
        self.by_id.entry(inv.apc_id).or_default().push(inv);
    }

    /// Merge all invocations from `other` into `self` (draining `other`), preserving per-id order.
    pub fn append(&mut self, other: &mut ApcInvocations) {
        for (id, mut invs) in other.by_id.drain() {
            self.by_id.entry(id).or_default().append(&mut invs);
        }
    }

    /// Number of invocations (= APC chip rows) for `apc_id`.
    pub fn count(&self, apc_id: usize) -> usize {
        self.by_id.get(&apc_id).map_or(0, Vec::len)
    }

    /// Whether any invocation exists for `apc_id`.
    pub fn has(&self, apc_id: usize) -> bool {
        self.count(apc_id) > 0
    }

    /// The invocations for `apc_id`, in execution order.
    pub fn for_id(&self, apc_id: usize) -> &[ApcInvocation] {
        self.by_id.get(&apc_id).map_or(&[][..], Vec::as_slice)
    }

    /// Total invocations across all APC ids.
    pub fn len(&self) -> usize {
        self.by_id.values().map(Vec::len).sum()
    }

    /// Whether there are no invocations at all.
    pub fn is_empty(&self) -> bool {
        self.by_id.values().all(Vec::is_empty)
    }
}

// `ApcInvocation` holds an `Arc<[MemValue]>` (shared shard read-oracle) and `MemValue` doesn't
// implement `DeepSizeOf`, so derive isn't possible; approximate the owned heap of the stored
// invocations (the shared oracle is counted once by the shard, not per invocation).
impl DeepSizeOf for ApcInvocations {
    fn deep_size_of_children(&self, _context: &mut Context) -> usize {
        self.by_id.values().map(|v| v.capacity() * std::mem::size_of::<ApcInvocation>()).sum()
    }
}

#[derive(Debug)]
/// A snapshot of the parts of the execution record that change while an APC block runs, taken at
/// the block's entry and exit. `apply_calls` diffs the two event counters across a call, and
/// `capture_invocations` slices the block's read range from the read-oracle cursor. Everything else
/// in the record is either unchanged during an APC or regenerated by the APC chip's re-execution,
/// so it need not be snapshotted.
pub struct ExecutionRecordSnapshot {
    pub cpu_event_count: u32,
    pub global_interaction_event_count: u32,
    /// Read-oracle cursor at this snapshot (see `ExecutionRecord::mem_reads_remaining`). Used to
    /// slice an APC invocation's read range from the shard read-oracle for re-execution.
    pub mem_reads_remaining: usize,
}
