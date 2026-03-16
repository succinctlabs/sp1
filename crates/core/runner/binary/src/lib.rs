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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    pub public_values_stream: Vec<u8>,
    pub hints: Vec<(u64, Vec<u8>)>,
    pub global_clk: u64,
    pub exit_code: u32,
}
