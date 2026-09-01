use std::{
    collections::VecDeque,
    fs::File,
    io::{Seek, Write},
};

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use sp1_hypercube::{MachineVerifyingKey, SP1PcsProofInner};

use crate::{
    events::{MemoryEntry, PageProtRecord},
    memory::Memory,
    SP1RecursionProof, SyscallCode,
};

use sp1_primitives::SP1GlobalContext;

/// Holds data describing the current state of a program's execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct ExecutionState {
    /// The program counter.
    pub pc: u64,

    /// Whether or not the shard is finished.
    pub shard_finished: bool,

    /// The starting timestamp of the current shard.
    pub initial_timestamp: u64,

    /// The memory which instructions operate over. Values contain the memory value and last shard
    /// + timestamp that each memory address was accessed.
    pub memory: Memory<MemoryEntry>,

    /// The page protection flags for each page in the memory.  The default values should be
    /// `PROT_READ` | `PROT_WRITE`.
    pub page_prots: HashMap<u64, PageProtRecord>,

    /// The global clock keeps track of how many instructions have been executed through all
    /// shards.
    pub global_clk: u64,

    /// The clock increments by 4 (possibly more in syscalls) for each instruction that has been
    /// executed in this shard.
    pub clk: u64,

    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// `SyscallHintRead` uses this to write hint data into uninitialized memory.
    pub uninitialized_memory: Memory<u64>,

    /// A stream of input values (global to the entire program).
    pub input_stream: VecDeque<Vec<u8>>,

    /// A stream of proofs (reduce vk, proof, verifying key) inputted to the program.
    pub proof_stream: Vec<(
        SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>,
        MachineVerifyingKey<SP1GlobalContext>,
    )>,

    /// A ptr to the current position in the proof stream, incremented after verifying a proof.
    pub proof_stream_ptr: usize,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// A ptr to the current position in the public values stream, incremented when reading from
    /// `public_values_stream`.
    pub public_values_stream_ptr: usize,

    /// Keeps track of how many times a certain syscall has been called.
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

impl ExecutionState {
    #[must_use]
    /// Create a new [`ExecutionState`].
    pub fn new(pc_start: u64) -> Self {
        Self {
            global_clk: 0,
            shard_finished: false,
            initial_timestamp: 1,
            clk: 0,
            pc: pc_start,
            memory: Memory::new_preallocated(),
            page_prots: HashMap::new(),
            uninitialized_memory: Memory::new_preallocated(),
            input_stream: VecDeque::new(),
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            proof_stream: Vec::new(),
            proof_stream_ptr: 0,
            syscall_counts: HashMap::new(),
        }
    }

    /// Save the execution state to a file.
    pub fn save(&self, file: &mut File) -> std::io::Result<()> {
        let mut writer = std::io::BufWriter::new(file);
        bincode::serialize_into(&mut writer, self).unwrap();
        writer.flush()?;
        writer.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }
}
