use std::{marker::PhantomData, sync::Arc};

use serde::{Deserialize, Serialize};
use slop_merkle_tree::batch_update::{BatchMerkleProof, Digest};
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::{MemReads, MemValue, MinimalTrace, TraceChunk};
use sp1_primitives::consts::LOG_PAGE_SIZE;

use crate::{
    events::{MemoryLocalEvent, MemoryReadRecord, MemoryRecord, MemoryWriteRecord, PageProtRecord},
    vm::{
        results::{
            CycleResult, FetchResult, LoadResult, LoadResultSupervisor, StoreResult,
            StoreResultSupervisor, TrapResult,
        },
        shapes::{ShapeChecker, HALT_AREA, HALT_HEIGHT},
        syscall::SyscallRuntime,
        CoreVM,
    },
    ExecutionError, ExecutionMode, Instruction, Opcode, Program, SP1CoreOpts, ShardingThreshold,
    SupervisorMode, SyscallCode, TrapError, UserMode,
};

pub use sp1_jit::merkle::MERKLE_PAGE_WORDS;
/// Bytes per merkle page.
pub const MERKLE_PAGE_BYTES: u64 = (MERKLE_PAGE_WORDS as u64) * 8;

/// A RISC-V VM that uses a [`MinimalTrace`] to create multiple [`SplicedMinimalTrace`]s.
///
/// These new [`SplicedMinimalTrace`]s correspond to exactly 1 execuction shard to be proved.
///
/// Note that this is the only time we account for trace area throught the execution pipeline.
///
/// The type parameter `M` determines whether page protection checks are enabled.
pub struct SplicingVM<'a, M: ExecutionMode> {
    /// The core VM.
    pub core: CoreVM<'a, M>,
    /// The shape checker, responsible for cutting the execution when a shard limit is reached.
    pub shape_checker: ShapeChecker<M>,
    /// Per-chunk workspace tracking initial page contents + per-address `last_clk` for the
    /// merkle-memory reconstruction. Empty until [`SplicingVM::set_dirty_pages`] is called.
    pub per_chunk: PerChunkState,
    /// Phantom data for the execution mode.
    _mode: PhantomData<M>,
}

/// Per-chunk state for merkle-memory reconstruction.
///
/// The set of pages touched in the chunk is supplied up-front via [`SplicingVM::set_dirty_pages`],
/// so we use a flat open-addressed `page_id -> page_idx` table backed by a dense `Vec<PageState>`.
///
/// Also, we track the initial/final clk and values of the touched addresses for each shard.
pub struct PerChunkState {
    /// Open-addressed `page_id -> page_idx` table.
    lookup: Box<[u64]>,
    /// The cached value of `lookup.len() - 1` as a `u32`.
    lookup_mask: u32,
    /// Dense per-page state, indexed by `page_idx`.
    pages: Vec<PageState>,
    /// `page_id` for each `page_idx` (parallel to `pages`).
    page_ids: Vec<u32>,
    /// The `page_id` of the most recently accessed page (or `u32::MAX` if none).
    cache_last_page_id: u32,
    /// The dense `page_idx` paired with `cache_last_ptr`.
    cache_last_page_idx: u32,
    /// The pointer into `pages` for `cache_last_page_id` (null when no cache).
    cache_last_ptr: *mut PageState,
    /// List of addresses and their initial clk, value touched in the current shard.
    shard_touched: Vec<ShardTouch>,
    /// Snapshot of `core.registers()` at the start of the current shard.
    shard_initial_registers: [MemoryRecord; 32],
    /// Snapshot of `core.registers()` at the start of the chunk.
    chunk_initial_registers: [MemoryRecord; 32],
    /// Snapshot of `core.registers()` at the end of the most recent shard.
    chunk_final_registers: [MemoryRecord; 32],
    /// The [`ShardData`] for the most recently cut shard. This should be drained for
    /// each shard via [`PerChunkState::take_pending_shard`].
    pending_shard: Option<ShardData>,
}

/// A snapshot of the initial state of an address at the start of a shard.
#[repr(C)]
#[derive(Clone, Copy)]
struct ShardTouch {
    /// `(page_idx as u64) << 32 | (word_idx as u64)`.
    location: u64,
    /// The initial memory record at `addr`.
    initial: MemoryRecord,
}

/// Per-shard view of memory and register accesses.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ShardData {
    /// The addresses touched in the shard and their initial / final states.
    pub entries: Vec<MemoryLocalEvent>,
}

impl deepsize2::DeepSizeOf for ShardData {
    fn deep_size_of_children(&self, _context: &mut deepsize2::Context) -> usize {
        0
    }
}

/// Per-chunk merkle reconstruction payload.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleProvingPayload {
    /// The `page_id` of the touched pages in the `TraceChunk`.
    pub page_ids: Vec<u32>,
    /// The state of each touched pages in the `TraceChunk`.
    pub pages: Vec<PageState>,
}

/// The result of preparing a chunk's batch merkle proof.
/// [`crate::ExecutionRecord::from_merkle_proof_record`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleProofRecord {
    /// The per-chunk touched-page reconstruction payload.
    pub payload: MerkleProvingPayload,
    /// The batch Merkle proof in column form.
    pub proof: BatchMerkleProof,
    /// The leaf hashes of the touched pages before this chunk (parallel to `payload.page_ids`).
    pub prev_leaves: Vec<Digest>,
    /// The leaf hashes of the touched pages after this chunk (parallel to `payload.page_ids`).
    pub new_leaves: Vec<Digest>,
}

impl deepsize2::DeepSizeOf for MerkleProofRecord {
    fn deep_size_of_children(&self, _context: &mut deepsize2::Context) -> usize {
        0
    }
}

/// Borrowed view of [`MerkleProvingPayload`] for in-place serialization without an
/// intermediate allocation. Same byte layout as the owned variant.
#[derive(Serialize)]
pub struct MerkleProvingPayloadRef<'a> {
    /// The `page_id` of the touched pages in the `TraceChunk`.
    pub page_ids: &'a [u32],
    /// The state of each touched pages in the `TraceChunk`.
    pub pages: &'a [PageState],
}

/// Per-page bookkeeping captured by [`SplicingVM`] during a chunk pass.
/// The mapping `page_id -> page_idx` lives in the parent [`PerChunkState`].
#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageState {
    /// Value at `addr` at chunk start. Initialized in `set_dirty_pages` from the page's chunk's
    /// final contents. For words that are not accessed in this chunk, chunk-end value
    /// equals chunk-start value, so the initialization is the correct answer. For words
    /// that are accessed in this chunk, `on_access` overwrites this slot on first
    /// touch with the pre-value from the trace, which is the chunk-start value.
    #[serde(with = "serde_arrays")]
    pub initial_contents: [u64; MERKLE_PAGE_WORDS],
    /// Timestamp of the most recent access to `addr` in this chunk. `0` if never accessed.
    #[serde(with = "serde_arrays")]
    pub last_clk: [u64; MERKLE_PAGE_WORDS],
    /// Running value, updated on every traced access. Equal to chunk-end value at chunk close.
    #[serde(with = "serde_arrays")]
    pub final_values: [u64; MERKLE_PAGE_WORDS],
    /// 256-bit bitmap: bit `w` is set if word `w` has been touched in the current shard.
    pub shard_touched_bits: [u64; MERKLE_PAGE_WORDS / 64],
}

impl PerChunkState {
    /// Create an empty per-chunk state. No pages are tracked until
    /// [`SplicingVM::set_dirty_pages`] is called.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lookup: Box::new([]),
            lookup_mask: 0,
            pages: Vec::new(),
            page_ids: Vec::new(),
            cache_last_page_id: u32::MAX,
            cache_last_page_idx: 0,
            cache_last_ptr: std::ptr::null_mut(),
            shard_touched: Vec::new(),
            shard_initial_registers: [MemoryRecord::default(); 32],
            chunk_initial_registers: [MemoryRecord::default(); 32],
            chunk_final_registers: [MemoryRecord::default(); 32],
            pending_shard: None,
        }
    }

    /// Build the `page_id -> page_idx` lookup and allocate the dense `Vec<PageState>`.
    pub fn set_dirty_pages(
        &mut self,
        page_ids: &[u32],
        final_contents: &[[u64; MERKLE_PAGE_WORDS]],
    ) {
        assert_eq!(page_ids.len(), final_contents.len());

        let num_pages = page_ids.len();
        self.pages = (0..num_pages)
            .map(|i| PageState {
                initial_contents: final_contents[i],
                last_clk: [0; MERKLE_PAGE_WORDS],
                final_values: final_contents[i],
                shard_touched_bits: [0; MERKLE_PAGE_WORDS / 64],
            })
            .collect();
        self.page_ids = page_ids.to_vec();
        self.shard_touched = Vec::with_capacity(num_pages.saturating_mul(16));
        self.pending_shard = None;

        // Build the open-addressed lookup.
        let cap = (num_pages.saturating_mul(2)).max(1).next_power_of_two();
        let mut lookup = vec![u64::MAX; cap].into_boxed_slice();
        let mask = (cap - 1) as u32;
        for (idx, &pid) in page_ids.iter().enumerate() {
            let mut slot = (hash_u32(pid) & mask) as usize;
            while lookup[slot] != u64::MAX {
                debug_assert!(
                    (lookup[slot] as u32) != pid,
                    "duplicate page_id {pid} in set_dirty_pages",
                );
                slot = (slot + 1) & (mask as usize);
            }
            lookup[slot] = (pid as u64) | ((idx as u64) << 32);
        }

        self.lookup = lookup;
        self.lookup_mask = mask;
        self.cache_last_page_id = u32::MAX;
        self.cache_last_page_idx = 0;
        self.cache_last_ptr = std::ptr::null_mut();
    }

    /// Look up the `page_idx` for a given `page_id`.
    #[inline]
    fn page_idx_of(&self, pid: u32) -> u32 {
        assert!(
            !self.lookup.is_empty(),
            "PerChunkState lookup is empty — set_dirty_pages was not called before execution",
        );
        let mut slot = (hash_u32(pid) & self.lookup_mask) as usize;
        let mask = self.lookup_mask as usize;
        loop {
            let e = unsafe { *self.lookup.get_unchecked(slot) };
            assert!(e != u64::MAX, "page_id {pid} not in dirty_pages — invariant violation");
            if (e as u32) == pid {
                return (e >> 32) as u32;
            }
            slot = (slot + 1) & mask;
        }
    }

    /// Record an access at byte address `addr` (must be 8-byte aligned).
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn on_access(
        &mut self,
        addr: u64,
        pre_value: u64,
        post_value: u64,
        current_clk: u64,
    ) -> u64 {
        let page_id = (addr / MERKLE_PAGE_BYTES) as u32;
        let word_idx = ((addr / 8) as usize) & (MERKLE_PAGE_WORDS - 1);

        let (page_ptr, page_idx): (*mut PageState, u32) = if page_id == self.cache_last_page_id {
            (self.cache_last_ptr, self.cache_last_page_idx)
        } else {
            let idx = self.page_idx_of(page_id);
            // SAFETY: `set_dirty_pages` allocated `pages` with `num_pages` entries and
            // assigned each index to an entry of the lookup. We never reallocate `pages` after.
            let p = unsafe { self.pages.as_mut_ptr().add(idx as usize) };
            self.cache_last_page_id = page_id;
            self.cache_last_page_idx = idx;
            self.cache_last_ptr = p;
            (p, idx)
        };

        // SAFETY: page_ptr is in-bounds of `self.pages` and aliases nothing else.
        let (prev_clk, first_in_shard) = unsafe {
            let page = &mut *page_ptr;
            let prev_clk = *page.last_clk.get_unchecked(word_idx);
            if prev_clk == 0 {
                *page.initial_contents.get_unchecked_mut(word_idx) = pre_value;
            }
            let qword = word_idx >> 6;
            let bit = 1u64 << (word_idx & 63);
            let bits_slot = page.shard_touched_bits.get_unchecked_mut(qword);
            let first = (*bits_slot & bit) == 0;
            if first {
                *bits_slot |= bit;
            }
            *page.last_clk.get_unchecked_mut(word_idx) = current_clk;
            *page.final_values.get_unchecked_mut(word_idx) = post_value;
            (prev_clk, first)
        };

        if first_in_shard {
            let location = ((page_idx as u64) << 32) | (word_idx as u64);
            self.shard_touched.push(ShardTouch {
                location,
                initial: MemoryRecord { value: pre_value, timestamp: prev_clk },
            });
        }
        prev_clk
    }

    /// Finalize the current shard. Projects `shard_touched` + the register-file snapshots
    /// into a [`ShardData`], stores it in `pending_shard` for the consumer to drain via
    /// [`take_pending_shard`], advances `shard_initial_registers` to `current_registers`
    /// for the next shard, and (unless `is_final`) clears the per-word bitmap on every
    /// touched page. Panics if a previously pending shard has not been drained.
    pub fn finish_shard(&mut self, is_final: bool, current_registers: &[MemoryRecord; 32]) {
        assert!(
            self.pending_shard.is_none(),
            "finish_shard called before previous pending_shard was taken",
        );
        let n = self.shard_touched.len();
        let mut data = ShardData { entries: Vec::with_capacity(n + 32) };
        for &touch in &self.shard_touched {
            let page_idx = (touch.location >> 32) as u32;
            let word_idx = (touch.location as u32) as usize;
            let page = &self.pages[page_idx as usize];
            let page_id = self.page_ids[page_idx as usize];
            data.entries.push(MemoryLocalEvent {
                addr: (page_id as u64) * MERKLE_PAGE_BYTES + (word_idx as u64) * 8,
                initial_mem_access: touch.initial,
                final_mem_access: MemoryRecord {
                    value: page.final_values[word_idx],
                    timestamp: page.last_clk[word_idx],
                },
            });
        }
        // Emit an event for every register.
        for r in 0..32 {
            data.entries.push(MemoryLocalEvent {
                addr: r as u64,
                initial_mem_access: self.shard_initial_registers[r],
                final_mem_access: current_registers[r],
            });
        }
        if !is_final {
            for &touch in &self.shard_touched {
                let page_idx = (touch.location >> 32) as u32;
                let word_idx = (touch.location as u32) as usize;
                let qword = word_idx >> 6;
                self.pages[page_idx as usize].shard_touched_bits[qword] = 0;
            }
        }
        self.shard_touched.clear();
        self.shard_initial_registers = *current_registers;
        self.chunk_final_registers = *current_registers;
        if is_final {
            self.finalize_register_page();
        }
        self.pending_shard = Some(data);
    }

    /// At chunk end, project the register file into page 0's [`PageState`].
    fn finalize_register_page(&mut self) {
        let Some(idx) = self.page_idx_of_pub(0) else { return };
        let init = self.chunk_initial_registers;
        let fin = self.chunk_final_registers;
        let page = &mut self.pages[idx as usize];
        for r in 0..32 {
            page.initial_contents[r] = init[r].value;
            page.final_values[r] = fin[r].value;
            page.last_clk[r] = fin[r].timestamp;
        }
    }

    /// Move the just-finalized shard out for the consumer to forward downstream.
    /// Returns `None` if no shard has been finalized since the last call.
    pub fn take_pending_shard(&mut self) -> Option<ShardData> {
        self.pending_shard.take()
    }

    /// Number of pages currently tracked. `0` until `set_dirty_pages` is called.
    #[must_use]
    pub fn num_pages(&self) -> usize {
        self.pages.len()
    }

    /// Per-page state, dense slice indexed by `page_idx`.
    #[must_use]
    pub fn pages(&self) -> &[PageState] {
        &self.pages
    }

    /// Borrowed view of this chunk's merkle reconstruction payload.
    #[must_use]
    pub fn as_merkle_proving_payload(&self) -> MerkleProvingPayloadRef<'_> {
        MerkleProvingPayloadRef { page_ids: &self.page_ids, pages: &self.pages }
    }

    /// Consume this chunk's per-chunk state into the owned [`MerkleProvingPayload`].
    #[must_use]
    pub fn into_merkle_proving_payload(mut self) -> MerkleProvingPayload {
        MerkleProvingPayload {
            page_ids: std::mem::take(&mut self.page_ids),
            pages: std::mem::take(&mut self.pages),
        }
    }

    /// Look up the dense `page_idx` for a merkle `page_id`, returning `None` if the page
    /// isn't in the tracked set. Public counterpart of the internal `page_idx_of`.
    #[must_use]
    pub fn page_idx_of_pub(&self, pid: u32) -> Option<u32> {
        if self.lookup.is_empty() {
            return None;
        }
        let mut slot = (hash_u32(pid) & self.lookup_mask) as usize;
        let mask = self.lookup_mask as usize;
        for _ in 0..self.lookup.len() {
            let e = unsafe { *self.lookup.get_unchecked(slot) };
            if e == u64::MAX {
                return None;
            }
            if (e as u32) == pid {
                return Some((e >> 32) as u32);
            }
            slot = (slot + 1) & mask;
        }
        None
    }

    /// Iterate the merkle `page_id`s tracked in this chunk, in lookup-table-bucket order.
    pub fn iter_page_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.lookup.iter().filter_map(|&e| if e == u64::MAX { None } else { Some(e as u32) })
    }

    /// Verify per-shard invariants given the externally collected sequence of `ShardData`.
    pub fn verify_shard_invariants(&self, shards: &[ShardData]) {
        use std::collections::{HashMap, HashSet};

        for s in shards {
            let mut seen = HashSet::new();
            // Check that `entries` have no duplicates, and the memory addresses are touched.
            for e in &s.entries {
                assert!(seen.insert(e.addr));
                if e.addr < 32 {
                    // Register: may be unaccessed this shard (equal timestamps).
                    assert!(e.final_mem_access.timestamp >= e.initial_mem_access.timestamp);
                } else {
                    assert!(e.final_mem_access.timestamp > e.initial_mem_access.timestamp);
                }
            }
        }

        let mut last_final_per_addr: HashMap<u64, MemoryRecord> = HashMap::new();
        for s in shards {
            for e in &s.entries {
                // Check that the per-shard `MemoryLocalEvent` are contiguous.
                if let Some(&prev) = last_final_per_addr.get(&e.addr) {
                    assert_eq!(e.initial_mem_access, prev);
                }
                last_final_per_addr.insert(e.addr, e.final_mem_access);
            }
        }

        // Check that the final memory state is correctly derived.
        for (&addr, &last) in last_final_per_addr.iter() {
            let (pid, word_idx) = if addr < 32 {
                (0u32, addr as usize)
            } else {
                ((addr / MERKLE_PAGE_BYTES) as u32, ((addr / 8) as usize) & (MERKLE_PAGE_WORDS - 1))
            };
            let idx = self.page_idx_of_pub(pid).unwrap() as usize;
            let page = &self.pages[idx];
            assert_eq!(page.last_clk[word_idx], last.timestamp);
            assert_eq!(page.final_values[word_idx], last.value);
        }

        let mut chunk_touched: HashSet<u64> = HashSet::new();
        for pid in self.iter_page_ids() {
            // Page 0 is the register page.
            if pid == 0 {
                continue;
            }
            let idx = self.page_idx_of_pub(pid).unwrap() as usize;
            let page = &self.pages[idx];
            for word_idx in 0..MERKLE_PAGE_WORDS {
                if page.last_clk[word_idx] != 0 {
                    chunk_touched.insert((pid as u64) * MERKLE_PAGE_BYTES + (word_idx as u64) * 8);
                }
            }
        }

        // Check that the initial state is correctly derived.
        let mut shard_first_touches: HashSet<u64> = HashSet::new();
        for s in shards {
            for e in &s.entries {
                if e.addr < 32 {
                    continue;
                }
                if e.initial_mem_access.timestamp == 0 {
                    assert!(shard_first_touches.insert(e.addr));
                    let pid = (e.addr / MERKLE_PAGE_BYTES) as u32;
                    let word_idx = ((e.addr / 8) as usize) & (MERKLE_PAGE_WORDS - 1);
                    let idx = self.page_idx_of_pub(pid).unwrap() as usize;
                    let chunk_initial = self.pages[idx].initial_contents[word_idx];
                    assert_eq!(chunk_initial, e.initial_mem_access.value);
                }
            }
        }

        // Check that the set of touched memory addresses agree.
        assert_eq!(chunk_touched, shard_first_touches);
    }
}

impl Default for PerChunkState {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: `cache_last_ptr` is derived from `self.pages` (which `Self` owns). It is only
// dereferenced from inside `on_access` while we hold `&mut self`, so there is no aliasing.
// We do not share `PerChunkState` across threads.
unsafe impl Send for PerChunkState {}

/// Cheap multiplicative hash for `u32`.
#[allow(clippy::inline_always)]
#[inline(always)]
fn hash_u32(x: u32) -> u32 {
    x.wrapping_mul(0x9E37_79B9)
}

impl SplicingVM<'_, SupervisorMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            let mut result = self.execute_instruction()?;

            // If we're not already done, ensure that we don't have a shard boundary.
            if !result.is_done() && self.shape_checker.check_shard_limit() {
                result = CycleResult::ShardBoundary;
            }

            match result {
                CycleResult::Done(false) => {}
                CycleResult::ShardBoundary | CycleResult::TraceEnd => {
                    let is_final = self.core.is_trace_end();
                    // Refresh before snapshotting to let the register refresh happen.
                    self.start_new_shard();
                    let registers = *self.core.registers();
                    self.per_chunk.finish_shard(is_final, &registers);
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    let registers = *self.core.registers();
                    self.per_chunk.finish_shard(true, &registers);
                    return Ok(CycleResult::Done(true));
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let instruction = self.core.fetch();

        match &instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                self.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction);
            }
            Opcode::ECALL => self.execute_ecall(&instruction)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        self.shape_checker.handle_instruction(
            &instruction,
            self.core.needs_bump_clk_high(),
            instruction.is_alu_instruction() && instruction.op_a == 0,
            instruction.is_memory_load_instruction() && instruction.op_a == 0,
            self.core.needs_state_bump(&instruction),
        );

        Ok(self.core.advance())
    }
}

impl SplicingVM<'_, SupervisorMode> {
    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };

        let LoadResultSupervisor { addr, mr_record, .. } = self.core.execute_load(instruction)?;
        let aligned = addr & !0b111;

        let prev_clk = self.per_chunk.on_access(
            aligned,
            mr_record.value,
            mr_record.value,
            mr_record.timestamp,
        );

        unsafe { (*slot_ptr).clk = prev_clk };
        self.shape_checker.handle_mem_event(addr, prev_clk);

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };

        let StoreResultSupervisor { addr, mw_record, .. } = self.core.execute_store(instruction)?;
        let aligned = addr & !0b111;

        let prev_clk = self.per_chunk.on_access(
            aligned,
            mw_record.prev_value,
            mw_record.value,
            mw_record.timestamp,
        );

        unsafe { (*slot_ptr).clk = prev_clk };
        self.shape_checker.handle_mem_event(addr, prev_clk);

        Ok(())
    }
}

impl SplicingVM<'_, UserMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            let mut result = self.execute_instruction()?;

            // If we're not already done, ensure that we don't have a shard boundary.
            if !result.is_done() && self.shape_checker.check_shard_limit() {
                result = CycleResult::ShardBoundary;
            }

            match result {
                CycleResult::Done(false) => {}
                CycleResult::ShardBoundary | CycleResult::TraceEnd => {
                    self.start_new_shard();
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    return Ok(CycleResult::Done(true));
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let FetchResult { instruction, mr_record, pc, error } = self.core.fetch()?;
        let mut num_page_prot_accesses = 0;

        if let Some(error) = error {
            self.handle_error(error)?;
            let page_idx = pc >> LOG_PAGE_SIZE;
            self.shape_checker.handle_page_prot_event(
                page_idx,
                mr_record.unwrap().prev_page_prot_record.unwrap().timestamp,
            );
            num_page_prot_accesses += 1;
            self.shape_checker.handle_trap_exec_event();
            self.shape_checker
                .handle_trap_events(self.core().needs_bump_clk_high(), num_page_prot_accesses);
            return Ok(self.core.advance());
        }

        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        if let Some(mr_record) = mr_record {
            let instruction_value = (mr_record.value >> ((pc % 8) * 8)) as u32;
            self.shape_checker.handle_untrusted_instruction(instruction_value);
            self.shape_checker.handle_mem_event(pc & !0b111, mr_record.prev_timestamp);
            let page_idx = pc >> LOG_PAGE_SIZE;
            self.shape_checker.handle_page_prot_event(
                page_idx,
                mr_record.prev_page_prot_record.unwrap().timestamp,
            );
            num_page_prot_accesses += 1;
        }

        // SAFETY: The instruction is guaranteed to be valid as we checked for `is_none` above.
        let instruction = unsafe { instruction.unwrap_unchecked() };

        match &instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                self.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction);
            }
            Opcode::ECALL => self.execute_ecall(&instruction)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        if instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction() {
            num_page_prot_accesses += 1;
        }

        self.shape_checker.handle_instruction(
            &instruction,
            self.core.needs_bump_clk_high(),
            instruction.is_alu_instruction() && instruction.op_a == 0,
            instruction.is_memory_load_instruction() && instruction.op_a == 0,
            self.core.needs_state_bump(&instruction),
            num_page_prot_accesses,
        );

        Ok(self.core.advance())
    }
}

impl SplicingVM<'_, UserMode> {
    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    #[inline]
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { addr, mr_record, error, .. } = self.core.execute_load(instruction)?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.shape_checker.handle_trap_mem_event();
        } else {
            self.shape_checker.handle_mem_event(addr, mr_record.prev_timestamp);
            // TODO(rkm): re-derive clk for the read memory event.
        }

        if let Some(record) = mr_record.prev_page_prot_record {
            self.shape_checker.handle_page_prot_event(record.page_idx, record.timestamp);
        }

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    #[inline]
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResult { addr, mw_record, error, .. } = self.core.execute_store(instruction)?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.shape_checker.handle_trap_mem_event();
        } else {
            self.shape_checker.handle_mem_event(addr, mw_record.prev_timestamp);
            // TODO(rkm): re-derive clk for the write memory event.
        }

        if let Some(record) = mw_record.prev_page_prot_record {
            self.shape_checker.handle_page_prot_event(record.page_idx, record.timestamp);
        }

        Ok(())
    }
}

impl<M: ExecutionMode> SplicingVM<'_, M> {
    /// Splice a minimal trace, outputting a minimal trace for the NEXT shard.
    pub fn splice<T: MinimalTrace>(&self, trace: T) -> Option<SplicedMinimalTrace<T>> {
        // If the trace has been exhausted, then the last splice is all thats needed.
        if self.core.is_trace_end() || self.core.is_done() {
            return None;
        }

        let total_mem_reads = trace.num_mem_reads();

        Some(SplicedMinimalTrace::new(
            trace,
            self.core.registers().iter().map(|v| v.value).collect::<Vec<_>>().try_into().unwrap(),
            self.core.pc(),
            self.core.clk(),
            total_mem_reads as usize - self.core.mem_reads.len(),
        ))
    }

    // Indicate that a new shard is starting.
    fn start_new_shard(&mut self) {
        self.shape_checker.reset(self.core.clk());
        self.core.register_refresh();
    }
}

impl<'a, M: ExecutionMode> SplicingVM<'a, M> {
    /// Create a new full-tracing VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        let program_len = program.instructions.len() as u64;
        let ShardingThreshold { element_threshold, height_threshold } = opts.sharding_threshold;
        assert!(
            element_threshold >= HALT_AREA && height_threshold >= HALT_HEIGHT,
            "invalid sharding threshold"
        );

        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            shape_checker: ShapeChecker::new(
                program_len,
                trace.clk_start(),
                ShardingThreshold {
                    element_threshold: element_threshold - HALT_AREA,
                    height_threshold: height_threshold - HALT_HEIGHT,
                },
            ),
            _mode: PhantomData,
            per_chunk: PerChunkState::new(),
        }
    }

    /// Handles recoverable errors such as traps.
    pub fn handle_error(&mut self, e: TrapError) -> Result<(), ExecutionError> {
        let TrapResult { context, code_record, pc_record, handler_record } =
            self.core.handle_error(e)?;

        self.shape_checker.handle_mem_event(context, handler_record.prev_timestamp);
        self.shape_checker.handle_mem_event(context + 8, code_record.prev_timestamp);
        self.shape_checker.handle_mem_event(context + 16, pc_record.prev_timestamp);

        Ok(())
    }

    /// Provide the list of merkle pages the chunk can touch and each page's
    /// chunk-end contents. See [`PerChunkState::set_dirty_pages`] for details. The
    /// chunk-start register snapshot is taken from `self.core.registers()`.
    pub fn set_dirty_pages(
        &mut self,
        page_ids: &[u32],
        final_contents: &[[u64; MERKLE_PAGE_WORDS]],
    ) {
        self.per_chunk.set_dirty_pages(page_ids, final_contents);
        self.per_chunk.shard_initial_registers = *self.core.registers();
        self.per_chunk.chunk_initial_registers = *self.core.registers();
    }

    /// Pull the most recently finalized [`ShardData`] out, if any. Callers should drain
    /// after each `execute()` call that returned `ShardBoundary` or `Done(true)`.
    pub fn take_pending_shard(&mut self) -> Option<ShardData> {
        self.per_chunk.take_pending_shard()
    }

    /// Move the per-chunk merkle bookkeeping state out of the `SplicingVM`.
    pub fn take_per_chunk_state(&mut self) -> PerChunkState {
        std::mem::take(&mut self.per_chunk)
    }

    /// Execute an ALU instruction and emit the events.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn execute_alu(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_alu(instruction);
    }

    /// Execute a jump instruction and emit the events.
    #[inline]
    pub fn execute_jump(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_jump(instruction);
    }

    /// Execute a branch instruction and emit the events.
    #[inline]
    pub fn execute_branch(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_branch(instruction);
    }

    /// Execute a U-type instruction and emit the events.   
    #[inline]
    pub fn execute_utype(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_utype(instruction);
    }

    /// Execute an ecall instruction and emit the events.
    #[inline]
    pub fn execute_ecall(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let code = self.core.read_code();

        if code.should_send() == 1 {
            self.shape_checker.handle_retained_syscall(code);
        }

        if code == SyscallCode::COMMIT || code == SyscallCode::COMMIT_DEFERRED_PROOFS {
            self.shape_checker.handle_commit();
        }

        let result = CoreVM::execute_ecall(self, instruction, code)?;

        if let Some(error) = result.error {
            self.handle_error(error)?;
        }

        if let Some(record) = result.sig_return_pc_record {
            self.shape_checker.handle_mem_event(result.b, record.prev_timestamp);
        }

        Ok(())
    }
}

impl<'a, M: ExecutionMode> SyscallRuntime<'a, M> for SplicingVM<'a, M> {
    const TRACING: bool = false;

    fn core(&self) -> &CoreVM<'a, M> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M> {
        &mut self.core
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);
        record
    }

    fn rw(&mut self, register: usize, value: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::rw(self.core_mut(), register, value);
        record
    }

    fn page_prot_write(&mut self, page_idx: u64, prot: u8) -> PageProtRecord {
        let prev_page_prot_record = self.core_mut().page_prot_write(page_idx, prot);
        self.shape_checker.handle_page_prot_event(
            prev_page_prot_record.page_idx,
            prev_page_prot_record.timestamp,
        );
        prev_page_prot_record
    }

    fn page_prot_range_check(
        &mut self,
        start_page_idx: u64,
        end_page_idx: u64,
        page_prot_bitmap: u8,
    ) -> (Vec<PageProtRecord>, Option<TrapError>) {
        let (page_prot_records, error) =
            self.core_mut().page_prot_range_check(start_page_idx, end_page_idx, page_prot_bitmap);
        for record in page_prot_records.iter() {
            self.shape_checker.handle_page_prot_event(record.page_idx, record.timestamp);
        }
        (page_prot_records, error)
    }

    fn mr_without_prot(&mut self, addr: u64) -> MemoryReadRecord {
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };
        let record = self.core_mut().mr_without_prot(addr);

        let prev_clk = self.per_chunk.on_access(addr, record.value, record.value, record.timestamp);
        unsafe { (*slot_ptr).clk = prev_clk };
        self.shape_checker.handle_mem_event(addr, prev_clk);

        record
    }

    fn mw_without_prot(&mut self, addr: u64) -> MemoryWriteRecord {
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };
        let record = self.core_mut().mw_without_prot(addr);

        let prev_clk =
            self.per_chunk.on_access(addr, record.prev_value, record.value, record.timestamp);
        unsafe {
            (*slot_ptr).clk = prev_clk;
            (*slot_ptr.add(1)).clk = record.timestamp;
        }
        self.shape_checker.handle_mem_event(addr, prev_clk);

        record
    }

    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };
        let records = self.core_mut().mr_slice_without_prot(addr, len);

        for (i, record) in records.iter().enumerate() {
            let entry_addr = addr + (i as u64) * 8;
            let prev_clk =
                self.per_chunk.on_access(entry_addr, record.value, record.value, record.timestamp);
            unsafe { (*slot_ptr.add(i)).clk = prev_clk };
            self.shape_checker.handle_mem_event(entry_addr, prev_clk);
        }

        records
    }

    fn mw_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        // Use the `CoreVM`'s current clk as the memory access clk.
        let current_clk = self.core.clk();
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };
        let records = self.core_mut().mw_slice_without_prot(addr, len);

        for (i, record) in records.iter().enumerate() {
            let entry_addr = addr + (i as u64) * 8;
            let prev_clk =
                self.per_chunk.on_access(entry_addr, record.prev_value, record.value, current_clk);
            unsafe {
                (*slot_ptr.add(2 * i)).clk = prev_clk;
                (*slot_ptr.add(2 * i + 1)).clk = current_clk;
            }
            self.shape_checker.handle_mem_event(entry_addr, prev_clk);
        }

        records
    }

    fn mw_hint_slice(&mut self, addr: u64, len_words: usize) -> Vec<MemoryWriteRecord> {
        // For hints, the previous clk and value are considered to be zero.
        let current_clk = self.core.clk();
        let slot_ptr = unsafe { self.core.mem_reads().head_raw_mut() };

        let mem_reads = self.core_mut().mem_reads();

        let records: Vec<MemoryWriteRecord> = mem_reads
            .take(len_words)
            .map(|value| MemoryWriteRecord {
                prev_timestamp: 0,
                prev_value: 0,
                value: value.value,
                timestamp: current_clk,
                prev_page_prot_record: None,
            })
            .collect();

        for i in 0..len_words {
            let word_addr = addr + (i as u64) * 8;
            let post_value = unsafe { (*slot_ptr.add(i)).value };
            let prev_clk = self.per_chunk.on_access(word_addr, 0, post_value, current_clk);
            unsafe {
                (*slot_ptr.add(i)).clk = current_clk;
            }
            self.shape_checker.handle_mem_event(word_addr, prev_clk);
        }

        records
    }
}

/// A minimal trace implentation that starts at a different point in the trace,
/// but reuses the same memory reads and hint lens.
///
/// Note: This type implements [`Serialize`] but it is serialized as a [`TraceChunk`].
///
/// In order to deserialize this type, you must use the [`TraceChunk`] type.
#[derive(Debug, Clone)]
pub struct SplicedMinimalTrace<T: MinimalTrace> {
    inner: T,
    start_registers: [u64; 32],
    start_pc: u64,
    start_clk: u64,
    memory_reads_idx: usize,
    last_clk: u64,
    // Normally unused but can be set for the cluster.
    last_mem_reads_idx: usize,
}

impl<T: MinimalTrace> SplicedMinimalTrace<T> {
    /// Create a new spliced minimal trace.
    #[tracing::instrument(name = "SplicedMinimalTrace::new", skip(inner), level = "trace")]
    pub fn new(
        inner: T,
        start_registers: [u64; 32],
        start_pc: u64,
        start_clk: u64,
        memory_reads_idx: usize,
    ) -> Self {
        Self {
            inner,
            start_registers,
            start_pc,
            start_clk,
            memory_reads_idx,
            last_clk: 0,
            last_mem_reads_idx: 0,
        }
    }

    /// Create a new spliced minimal trace from a minimal trace without any splicing.
    #[tracing::instrument(
        name = "SplicedMinimalTrace::new_full_trace",
        skip(trace),
        level = "trace"
    )]
    pub fn new_full_trace(trace: T) -> Self {
        let start_registers = trace.start_registers();
        let start_pc = trace.pc_start();
        let start_clk = trace.clk_start();

        tracing::trace!("start_pc: {}", start_pc);
        tracing::trace!("start_clk: {}", start_clk);
        tracing::trace!("trace.num_mem_reads(): {}", trace.num_mem_reads());

        Self::new(trace, start_registers, start_pc, start_clk, 0)
    }

    /// Set the last clock of the spliced minimal trace.
    pub fn set_last_clk(&mut self, clk: u64) {
        self.last_clk = clk;
    }

    /// Set the last memory reads index of the spliced minimal trace.
    pub fn set_last_mem_reads_idx(&mut self, mem_reads_idx: usize) {
        self.last_mem_reads_idx = mem_reads_idx;
    }
}

impl<T: MinimalTrace> MinimalTrace for SplicedMinimalTrace<T> {
    fn start_registers(&self) -> [u64; 32] {
        self.start_registers
    }

    fn pc_start(&self) -> u64 {
        self.start_pc
    }

    fn clk_start(&self) -> u64 {
        self.start_clk
    }

    fn clk_end(&self) -> u64 {
        self.last_clk
    }

    fn num_mem_reads(&self) -> u64 {
        self.inner.num_mem_reads() - self.memory_reads_idx as u64
    }

    fn mem_reads(&self) -> MemReads<'_> {
        let mut reads = self.inner.mem_reads();
        reads.advance(self.memory_reads_idx);

        reads
    }
}

impl<T: MinimalTrace> Serialize for SplicedMinimalTrace<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let len = self.last_mem_reads_idx - self.memory_reads_idx;
        let mem_reads = unsafe {
            let mem_reads_buf = Arc::new_uninit_slice(len);
            let start_mem_reads = self.mem_reads();
            let src_ptr = start_mem_reads.head_raw();
            std::ptr::copy_nonoverlapping(src_ptr, mem_reads_buf.as_ptr() as *mut MemValue, len);
            mem_reads_buf.assume_init()
        };

        let trace = TraceChunk {
            start_registers: self.start_registers,
            pc_start: self.start_pc,
            clk_start: self.start_clk,
            clk_end: self.last_clk,
            mem_reads,
        };

        trace.serialize(serializer)
    }
}

/// Wrapper enum to handle `SplicingVM` with different execution modes at runtime.
pub enum SplicingVMEnum<'a> {
    /// `SplicingVM` for `SupervisorMode`.
    Supervisor(SplicingVM<'a, SupervisorMode>),
    /// `SplicingVM` for `UserMode`.
    User(SplicingVM<'a, UserMode>),
}

impl<'a> SplicingVMEnum<'a> {
    /// Create a new `SplicingVMEnum` based on program's `enable_untrusted_programs` flag.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        if program.enable_untrusted_programs {
            Self::User(SplicingVM::<UserMode>::new(trace, program, proof_nonce, opts))
        } else {
            Self::Supervisor(SplicingVM::<SupervisorMode>::new(trace, program, proof_nonce, opts))
        }
    }

    /// Execute the program until it halts or reaches a shard boundary.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        match self {
            Self::Supervisor(vm) => vm.execute(),
            Self::User(vm) => vm.execute(),
        }
    }

    /// Splice a minimal trace, outputting a minimal trace for the NEXT shard.
    pub fn splice<T: MinimalTrace>(&self, trace: T) -> Option<SplicedMinimalTrace<T>> {
        match self {
            Self::Supervisor(vm) => vm.splice(trace),
            Self::User(vm) => vm.splice(trace),
        }
    }

    /// Get the current clock.
    #[must_use]
    pub fn clk(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.clk(),
            Self::User(vm) => vm.core.clk(),
        }
    }

    /// Get the global clock.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.global_clk(),
            Self::User(vm) => vm.core.global_clk(),
        }
    }

    /// Get the current PC.
    #[must_use]
    pub fn pc(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.pc(),
            Self::User(vm) => vm.core.pc(),
        }
    }

    /// Get the number of remaining memory reads.
    #[must_use]
    pub fn mem_reads_len(&self) -> usize {
        match self {
            Self::Supervisor(vm) => vm.core.mem_reads.len(),
            Self::User(vm) => vm.core.mem_reads.len(),
        }
    }

    /// Get the registers.
    #[must_use]
    pub fn registers(&self) -> [MemoryRecord; 32] {
        match self {
            Self::Supervisor(vm) => *vm.core.registers(),
            Self::User(vm) => *vm.core.registers(),
        }
    }

    /// Get the exit code.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        match self {
            Self::Supervisor(vm) => vm.core.exit_code(),
            Self::User(vm) => vm.core.exit_code(),
        }
    }

    /// Check if done.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match self {
            Self::Supervisor(vm) => vm.core.is_done(),
            Self::User(vm) => vm.core.is_done(),
        }
    }

    /// Get the public value digest.
    #[must_use]
    pub fn public_value_digest(&self) -> [u32; sp1_hypercube::air::PV_DIGEST_NUM_WORDS] {
        match self {
            Self::Supervisor(vm) => vm.core.public_value_digest,
            Self::User(vm) => vm.core.public_value_digest,
        }
    }

    /// Get the proof nonce.
    #[must_use]
    pub fn proof_nonce(&self) -> [u32; sp1_hypercube::air::PROOF_NONCE_NUM_WORDS] {
        match self {
            Self::Supervisor(vm) => vm.core.proof_nonce,
            Self::User(vm) => vm.core.proof_nonce,
        }
    }

    /// Provide the chunk's dirty-page set + each page's chunk-end contents to the
    /// inner VM. Must be called before `execute()` for merkle bookkeeping to track
    /// page state.
    pub fn set_dirty_pages(
        &mut self,
        page_ids: &[u32],
        final_contents: &[[u64; MERKLE_PAGE_WORDS]],
    ) {
        match self {
            Self::Supervisor(vm) => vm.set_dirty_pages(page_ids, final_contents),
            Self::User(vm) => vm.set_dirty_pages(page_ids, final_contents),
        }
    }

    /// Pull the most recently finalized `ShardData`. Drain after every `execute()`
    /// that returned `ShardBoundary` or `Done(true)`.
    pub fn take_pending_shard(&mut self) -> Option<ShardData> {
        match self {
            Self::Supervisor(vm) => vm.take_pending_shard(),
            Self::User(vm) => vm.take_pending_shard(),
        }
    }

    /// Move the per-chunk merkle bookkeeping state out of the VM. Call after the
    /// chunk has finished executing (post-`Done(true)`).
    pub fn take_per_chunk_state(&mut self) -> PerChunkState {
        match self {
            Self::Supervisor(vm) => vm.take_per_chunk_state(),
            Self::User(vm) => vm.take_per_chunk_state(),
        }
    }
}

#[cfg(test)]
mod tests {
    use sp1_jit::MemValue;
    use test_artifacts::SSZ_WITHDRAWALS_ELF;

    use super::*;

    #[test]
    fn test_serialize_spliced_minimal_trace() {
        let trace_chunk = TraceChunk {
            start_registers: [1; 32],
            pc_start: 2,
            clk_start: 3,
            clk_end: 4,
            mem_reads: Arc::new([MemValue { clk: 8, value: 9 }, MemValue { clk: 10, value: 11 }]),
        };

        let mut trace = SplicedMinimalTrace::new(trace_chunk, [2; 32], 2, 3, 1);
        trace.set_last_mem_reads_idx(2);
        trace.set_last_clk(2);

        let serialized = bincode::serialize(&trace).unwrap();
        let deserialized: TraceChunk = bincode::deserialize(&serialized).unwrap();

        let expected = TraceChunk {
            start_registers: [2; 32],
            pc_start: 2,
            clk_start: 3,
            clk_end: 2,
            mem_reads: Arc::new([MemValue { clk: 10, value: 11 }]),
        };

        assert_eq!(deserialized, expected);
    }

    /// Correctness check for the per-chunk `SplicingVM` clk re-derivation.
    #[test]
    fn test_splicing_vm_clk_derivation() {
        use crate::minimal::arch::portable::MinimalExecutor;
        use sp1_jit::TraceChunkRaw;

        let program = Arc::new(Program::from(&SSZ_WITHDRAWALS_ELF).expect("parse fibonacci elf"));
        let mut executor =
            MinimalExecutor::<SupervisorMode>::new(program.clone(), false, Some(100_000_000));
        let raw: TraceChunkRaw = executor.execute_chunk().expect("expected at least one chunk");

        let mut chunk: TraceChunk = TraceChunk::from(raw);
        let expected: Vec<MemValue> = chunk.mem_reads.iter().copied().collect();

        // Dirty-page list and chunk-end page contents, straight from the executor.
        let dirty = executor.emit_dirty_pages();
        let pages: Vec<u32> = dirty.pages.iter().map(|p| p.page_id).collect();
        let final_contents: Vec<[u64; MERKLE_PAGE_WORDS]> =
            dirty.pages.iter().map(|p| p.final_contents).collect();

        // Zero out the clks. These will be re-derived in the `SplicingVM`.
        let mem_reads_mut = Arc::get_mut(&mut chunk.mem_reads)
            .expect("unique Arc ownership of mem_reads (we just constructed the chunk)");
        for mv in mem_reads_mut.iter_mut() {
            mv.clk = 0;
        }
        assert!(chunk.mem_reads.iter().any(|mv| expected.iter().any(|e| e.clk != mv.clk)));

        // Run the `SplicingVM` to re-derive the clk information.
        {
            let mut vm: SplicingVM<'_, SupervisorMode> = SplicingVM::new(
                &chunk,
                program.clone(),
                [0u32; PROOF_NONCE_NUM_WORDS],
                SP1CoreOpts::default(),
            );
            vm.set_dirty_pages(&pages, &final_contents);
            let _shards = run_to_end(&mut vm);

            // Check every dirty page has at least one traced access in the chunk.
            for page in vm.per_chunk.pages().iter() {
                assert!(page.last_clk.iter().any(|&c| c != 0));
            }
        }

        let actual: &[MemValue] = &chunk.mem_reads;
        assert_eq!(actual, expected);
    }

    /// Drive a `SplicingVM` through its trace until the program halts or trace boundary is
    /// reached, collecting `ShardData` as each shard finalizes.
    fn run_to_end(vm: &mut SplicingVM<'_, SupervisorMode>) -> Vec<ShardData> {
        let mut shards: Vec<ShardData> = Vec::new();
        loop {
            let res = vm.execute().expect("SplicingVM::execute");
            if let Some(d) = vm.take_pending_shard() {
                shards.push(d);
            }
            match res {
                CycleResult::Done(true) => break,
                CycleResult::ShardBoundary => {
                    if vm.core.is_trace_end() {
                        break;
                    }
                }
                CycleResult::Done(false) | CycleResult::TraceEnd => {
                    unreachable!("execute() should never return these directly");
                }
            }
        }
        shards
    }

    #[test]
    fn test_splicing_vm_shard_data() {
        use crate::minimal::arch::portable::MinimalExecutor;
        use sp1_jit::TraceChunkRaw;

        let program = Arc::new(Program::from(&SSZ_WITHDRAWALS_ELF).unwrap());
        let mut executor =
            MinimalExecutor::<SupervisorMode>::new(program.clone(), false, Some(10_000_000));
        let raw: TraceChunkRaw = executor.execute_chunk().unwrap();
        let chunk: TraceChunk = TraceChunk::from(raw);

        let dirty = executor.emit_dirty_pages();
        let pages: Vec<u32> = dirty.pages.iter().map(|p| p.page_id).collect();
        let final_contents: Vec<[u64; MERKLE_PAGE_WORDS]> =
            dirty.pages.iter().map(|p| p.final_contents).collect();

        let mut opts = SP1CoreOpts::default();
        opts.sharding_threshold.element_threshold = 1 << 24;
        let mut vm: SplicingVM<'_, SupervisorMode> =
            SplicingVM::new(&chunk, program.clone(), [0u32; PROOF_NONCE_NUM_WORDS], opts);
        vm.set_dirty_pages(&pages, &final_contents);

        let shards = run_to_end(&mut vm);
        assert!(!shards.is_empty());
        assert!(vm.per_chunk.take_pending_shard().is_none(),);

        vm.per_chunk.verify_shard_invariants(&shards);

        for e in &shards[0].entries {
            if e.addr < 32 {
                assert_eq!(e.initial_mem_access.timestamp, 0);
            }
        }
    }

    /// `MerkleProvingPayload` and the borrowed `MerkleProvingPayloadRef` must produce
    /// identical bincode bytes, serialization/deserialization should work correctly.
    #[test]
    fn test_merkle_payload_serde_roundtrip() {
        let mut state = PerChunkState::new();
        let final_contents = vec![[0u64; MERKLE_PAGE_WORDS]; 3];
        let page_ids = vec![10u32, 20, 30];
        state.set_dirty_pages(&page_ids, &final_contents);
        state.pages[0].initial_contents[5] = 0xdead_beef;
        state.pages[1].last_clk[0] = 42;
        state.pages[2].final_values[100] = 0xfeed_face;
        state.pages[1].shard_touched_bits[0] = 1u64 << 5;

        let ref_bytes = bincode::serialize(&state.as_merkle_proving_payload())
            .expect("borrowed payload serialize");

        let owned = state.into_merkle_proving_payload();
        let owned_bytes = bincode::serialize(&owned).expect("owned payload serialize");

        assert_eq!(ref_bytes, owned_bytes, "expected equal serialization result");

        let restored: MerkleProvingPayload =
            bincode::deserialize(&owned_bytes).expect("merkle payload deserialize");
        assert_eq!(restored.page_ids, vec![10, 20, 30]);
        assert_eq!(restored.pages.len(), 3);
        assert_eq!(restored.pages[0].initial_contents[5], 0xdead_beef);
        assert_eq!(restored.pages[1].last_clk[0], 42);
        assert_eq!(restored.pages[2].final_values[100], 0xfeed_face);
        assert_eq!(restored.pages[1].shard_touched_bits[0], 1u64 << 5);
    }

    // The serialization and deserialization should work correctly for `ShardData`.
    #[test]
    fn test_shard_data_serde_roundtrip() {
        let mk = |v: u64, t: u64| MemoryRecord { value: v, timestamp: t };
        let sd = ShardData {
            entries: vec![
                MemoryLocalEvent {
                    addr: 1,
                    initial_mem_access: mk(10, 100),
                    final_mem_access: mk(11, 101),
                },
                MemoryLocalEvent {
                    addr: 2,
                    initial_mem_access: mk(20, 200),
                    final_mem_access: mk(22, 202),
                },
                MemoryLocalEvent {
                    addr: 3,
                    initial_mem_access: mk(30, 300),
                    final_mem_access: mk(33, 303),
                },
            ],
        };

        let bytes = bincode::serialize(&sd).expect("ShardData serialize");
        let restored: ShardData = bincode::deserialize(&bytes).expect("ShardData deserialize");

        assert_eq!(restored.entries.len(), sd.entries.len());
        for (a, b) in restored.entries.iter().zip(sd.entries.iter()) {
            assert_eq!(a.addr, b.addr);
            assert_eq!(a.initial_mem_access, b.initial_mem_access);
            assert_eq!(a.final_mem_access, b.final_mem_access);
        }
    }
}
