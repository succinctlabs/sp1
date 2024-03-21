use std::collections::HashMap;

use nohash_hasher::BuildNoHashHasher;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{ExecutionRecord, MemoryAccessRecord, MemoryRecord};

/// Holds data describing the current state of a program's execution.
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionState {
    /// The global clock keeps track of how many instrutions have been executed through all shards.
    pub global_clk: u64,

    /// The shard clock keeps track of how many shards have been executed.
    pub current_shard: u32,

    /// The clock increments by 4 (possibly more in syscalls) for each instruction that has been
    /// executed in this shard.
    pub clk: u32,

    /// The program counter.
    pub pc: u32,

    /// The memory which instructions operate over. Values contain the memory value and last shard
    /// + timestamp that each memory address was accessed.
    pub memory: HashMap<u32, MemoryRecord, BuildNoHashHasher<u32>>,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<u8>,

    /// A ptr to the current position in the input stream incremented by LWA opcode.
    pub input_stream_ptr: usize,

    /// A stream of output values from the program (global to entire program).
    pub output_stream: Vec<u8>,

    /// A ptr to the current position in the output stream, incremented when reading from output_stream.
    pub output_stream_ptr: usize,
}

impl ExecutionState {
    pub fn new(pc_start: u32) -> Self {
        Self {
            global_clk: 0,
            // Start at shard 1 since shard 0 is reserved for memory initialization.
            current_shard: 1,
            clk: 0,
            pc: pc_start,
            memory: HashMap::default(),
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            output_stream: Vec::new(),
            output_stream_ptr: 0,
        }
    }
}

/// Holds data to track changes made to the runtime since a fork point.
#[derive(Debug, Clone, Default)]
pub(crate) struct ForkState {
    /// Original global_clk
    pub(crate) global_clk: u64,

    /// Original clk
    pub(crate) clk: u32,

    /// Original program counter
    pub(crate) pc: u32,

    /// Only contains the original memory values for addresses that have been modified
    pub(crate) memory_diff: HashMap<u32, Option<MemoryRecord>, BuildNoHashHasher<u32>>,

    /// Full record from original state
    pub(crate) op_record: MemoryAccessRecord,

    /// Full shard from original state
    pub(crate) record: ExecutionRecord,
}
