use std::collections::HashMap;

use nohash_hasher::BuildNoHashHasher;

use super::{CpuRecord, ExecutionRecord};

const SYSTEM_START: usize = 0x0C00_0000;
const MAX_MEMORY_SIZE: usize = 1 << 29;

#[derive(Clone)]
pub struct Memory(Vec<Option<(u32, u32, u32)>>, [Option<(u32, u32, u32)>; 32]);

impl Memory {
    #[inline]
    pub fn get(&self, addr: u32) -> Option<(u32, u32, u32)> {
        if addr < 32 {
            self.1[addr as usize]
        } else {
            self.0[(addr / 4) as usize]
        }
    }

    #[inline]
    pub fn get_mut(&mut self, addr: u32) -> &mut Option<(u32, u32, u32)> {
        // &mut self.0[(addr / 4) as usize]
        if addr < 32 {
            &mut self.1[addr as usize]
        } else {
            &mut self.0[(addr / 4) as usize]
        }
    }

    #[inline]
    pub fn remove(&mut self, addr: u32) {
        // self.0[(addr / 4) as usize] = None;
        if addr < 32 {
            self.1[addr as usize] = None;
        } else {
            self.0[(addr / 4) as usize] = None;
        }
    }

    #[inline]
    pub fn insert(&mut self, addr: u32, value: (u32, u32, u32)) {
        // self.0[(addr / 4) as usize] = Some(value);
        if addr < 32 {
            self.1[addr as usize] = Some(value);
        } else {
            self.0[(addr / 4) as usize] = Some(value);
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        // Self(Box::new([None; MAX_MEMORY_SIZE]))
        // Self(vec![None; MAX_MEMORY_SIZE / 4])
        let mut vec = Vec::with_capacity(MAX_MEMORY_SIZE / 4);
        vec.resize(MAX_MEMORY_SIZE / 4, None);
        Self(vec, [None; 32])
    }
}

impl std::fmt::Debug for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[Memory]")
    }
}

/// Holds data describing the current state of a program's execution.
#[derive(Debug, Clone, Default)]
pub struct ExecutionState {
    /// The global clock keeps track of how many instrutions have been executed through all shards.
    pub global_clk: u32,

    /// The shard clock keeps track of how many shards have been executed.
    pub current_shard: u32,

    /// The clock increments by 4 (possibly more in syscalls) for each instruction that has been
    /// executed in this shard.
    pub clk: u32,

    /// The program counter.
    pub pc: u32,

    /// The memory which instructions operate over. Values contain the memory value and last shard
    /// + timestamp that each memory address was accessed.
    // pub memory: HashMap<u32, (u32, u32, u32), BuildNoHashHasher<u32>>,
    pub memory: Memory,

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
            // Start at shard 1 since zero is reserved for memory initialization.
            current_shard: 1,
            clk: 0,
            pc: pc_start,
            memory: Memory::default(),
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
    pub(crate) global_clk: u32,

    /// Original clk
    pub(crate) clk: u32,

    /// Original program counter
    pub(crate) pc: u32,

    /// Only contains the original memory values for addresses that have been modified
    pub(crate) memory_diff: HashMap<u32, Option<(u32, u32, u32)>, BuildNoHashHasher<u32>>,

    /// Full record from original state
    pub(crate) op_record: CpuRecord,

    /// Full shard from original state
    pub(crate) record: ExecutionRecord,
}
