use std::{
    collections::HashMap,
    fs::File,
    io::{Seek, Write},
};

use nohash_hasher::BuildNoHashHasher;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{ExecutionRecord, MemoryAccessRecord, MemoryRecord, SyscallCode};
use crate::utils::{deserialize_hashmap_as_vec, serialize_hashmap_as_vec};
use crate::{
    stark::{ShardProof, StarkVerifyingKey},
    utils::BabyBearPoseidon2,
};

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

    /// The channel alternates between 0 and [crate::bytes::NUM_BYTE_LOOKUP_CHANNELS],
    /// used to controll byte lookup multiplicity.
    pub channel: u8,

    /// The program counter.
    pub pc: u32,

    /// The memory which instructions operate over. Values contain the memory value and last shard
    /// + timestamp that each memory address was accessed.
    #[serde(
        serialize_with = "serialize_hashmap_as_vec",
        deserialize_with = "deserialize_hashmap_as_vec"
    )]
    pub memory: HashMap<u32, MemoryRecord, BuildNoHashHasher<u32>>,

    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// SyscallHintRead uses this to write hint data into uninitialized memory.
    #[serde(
        serialize_with = "serialize_hashmap_as_vec",
        deserialize_with = "deserialize_hashmap_as_vec"
    )]
    pub uninitialized_memory: HashMap<u32, u32, BuildNoHashHasher<u32>>,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<Vec<u8>>,

    /// A ptr to the current position in the input stream incremented by HINT_READ opcode.
    pub input_stream_ptr: usize,

    /// A stream of proofs inputted to the program.
    pub proof_stream: Vec<(
        ShardProof<BabyBearPoseidon2>,
        StarkVerifyingKey<BabyBearPoseidon2>,
    )>,

    /// A ptr to the current position in the proof stream, incremented after verifying a proof.
    pub proof_stream_ptr: usize,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// A ptr to the current position in the public values stream, incremented when reading from public_values_stream.
    pub public_values_stream_ptr: usize,

    /// Keeps track of how many times a certain syscall has been called.
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

impl ExecutionState {
    pub fn new(pc_start: u32) -> Self {
        Self {
            global_clk: 0,
            // Start at shard 1 since shard 0 is reserved for memory initialization.
            current_shard: 1,
            clk: 0,
            channel: 0,
            pc: pc_start,
            memory: HashMap::default(),
            uninitialized_memory: HashMap::default(),
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            proof_stream: Vec::new(),
            proof_stream_ptr: 0,
            syscall_counts: HashMap::new(),
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

    // Emit events from original state
    pub(crate) emit_events: bool,
}

impl ExecutionState {
    pub fn save(&self, file: &mut File) -> std::io::Result<()> {
        let mut writer = std::io::BufWriter::new(file);
        bincode::serialize_into(&mut writer, self).unwrap();
        writer.flush()?;
        writer.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }
}
