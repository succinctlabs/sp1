use serde::{Deserialize, Serialize};
use sp1_core_executor::Program;
use std::{collections::VecDeque, sync::Arc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Input {
    pub program: Arc<Program>,
    pub is_debug: bool,
    pub max_trace_size: Option<u64>,
    pub input: VecDeque<Vec<u8>>,
    pub shm_slot_size: usize,
    pub id: String,
    pub max_memory_size: usize,
    pub memory_limit: u64,
    /// Per-slot byte size of the parallel dirty-pages ring. `None` (default)
    /// disables it: no ring, no per-chunk dirty pages (legacy behavior).
    /// `Some(slot_bytes)` opts in — the child writes a [`sp1_jit::DirtyPages`]
    /// payload per chunk, so `slot_bytes` must be ≥ `dirty_pages_wire_bytes(N)`
    /// for the worst-case N pages a chunk can emit.
    #[serde(default)]
    pub dirty_pages_slot_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    pub public_values_stream: Vec<u8>,
    pub hints: Vec<(u64, Vec<u8>)>,
    pub global_clk: u64,
    pub clk: u64,
    pub exit_code: u32,
    pub public_value_digest: [u32; sp1_jit::PUBLIC_VALUE_DIGEST_WORDS],
}
