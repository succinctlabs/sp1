#[cfg(feature = "profiling")]
use std::{fs::File, io::BufWriter};
use std::{str::FromStr, sync::Arc};

#[cfg(feature = "profiling")]
use crate::profiler::Profiler;
use clap::ValueEnum;
use enum_map::EnumMap;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use sp1_primitives::consts::BABYBEAR_PRIME;
use sp1_stark::{air::PublicValues, SP1CoreOpts};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::{
    context::SP1Context,
    dependencies::{
        emit_auipc_dependency, emit_branch_dependencies, emit_divrem_dependencies,
        emit_jump_dependencies, emit_memory_dependencies,
    },
    estimate_riscv_lde_size,
    events::{
        AUIPCEvent, AluEvent, BranchEvent, CpuEvent, JumpEvent, MemInstrEvent,
        MemoryAccessPosition, MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord,
        MemoryRecord, MemoryRecordEnum, MemoryWriteRecord, SyscallEvent,
        NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC,
    },
    hook::{HookEnv, HookRegistry},
    memory::{Entry, Memory},
    pad_rv32im_event_counts,
    record::{ExecutionRecord, MemoryAccessRecord},
    report::ExecutionReport,
    state::{ExecutionState, ForkState},
    subproof::SubproofVerifier,
    syscalls::{default_syscall_map, Syscall, SyscallCode, SyscallContext},
    CoreAirId, Instruction, MaximalShapes, Opcode, Program, Register, RiscvAirId,
};

/// The default increment for the program counter.  Is used for all instructions except
/// for branches and jumps.
pub const DEFAULT_PC_INC: u32 = 4;
/// This is used in the `InstrEvent` to indicate that the instruction is not from the CPU.
/// A valid pc should be divisible by 4, so we use 1 to indicate that the pc is not used.
pub const UNUSED_PC: u32 = 1;

/// The maximum number of instructions in a program.
pub const MAX_PROGRAM_SIZE: usize = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Whether to verify deferred proofs during execution.
pub enum DeferredProofVerification {
    /// Verify deferred proofs during execution.
    Enabled,
    /// Skip verification of deferred proofs
    Disabled,
}

impl From<bool> for DeferredProofVerification {
    fn from(value: bool) -> Self {
        if value {
            DeferredProofVerification::Enabled
        } else {
            DeferredProofVerification::Disabled
        }
    }
}

/// An executor for the SP1 RISC-V zkVM.
///
/// The exeuctor is responsible for executing a user program and tracing important events which
/// occur during execution (i.e., memory reads, alu operations, etc).
pub struct Executor<'a> {
    /// The program.
    pub program: Arc<Program>,

    /// The state of the execution.
    pub state: ExecutionState,

    /// Memory addresses that were touched in this batch of shards. Used to minimize the size of
    /// checkpoints.
    pub memory_checkpoint: Memory<Option<MemoryRecord>>,

    /// Memory addresses that were initialized in this batch of shards. Used to minimize the size of
    /// checkpoints. The value stored is whether or not it had a value at the beginning of the batch.
    pub uninitialized_memory_checkpoint: Memory<bool>,

    /// Report of the program execution.
    pub report: ExecutionReport,

    /// The mode the executor is running in.
    pub executor_mode: ExecutorMode,

    /// The memory accesses for the current cycle.
    pub memory_accesses: MemoryAccessRecord,

    /// Whether the runtime is in constrained mode or not.
    ///
    /// In unconstrained mode, any events, clock, register, or memory changes are reset after
    /// leaving the unconstrained block. The only thing preserved is writes to the input
    /// stream.
    pub unconstrained: bool,

    /// Whether we should write to the report.
    pub print_report: bool,

    /// Whether we should emit global memory init and finalize events. This can be enabled in
    /// Checkpoint mode and disabled in Trace mode.
    pub emit_global_memory_events: bool,

    /// The maximum size of each shard.
    pub shard_size: u32,

    /// The maximum number of shards to execute at once.
    pub shard_batch_size: u32,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: u32,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The options for the runtime.
    pub opts: SP1CoreOpts,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,

    /// The current trace of the execution that is being collected.
    pub record: Box<ExecutionRecord>,

    /// The collected records, split by cpu cycles.
    pub records: Vec<Box<ExecutionRecord>>,

    /// Local memory access events.
    pub local_memory_access: HashMap<u32, MemoryLocalEvent>,

    /// A counter for the number of cycles that have been executed in certain functions.
    pub cycle_tracker: HashMap<String, (u64, u32)>,

    /// A buffer for stdout and stderr IO.
    pub io_buf: HashMap<u32, String>,

    /// The ZKVM program profiler.
    ///
    /// Keeps track of the number of cycles spent in each function.
    #[cfg(feature = "profiling")]
    pub profiler: Option<(Profiler, BufWriter<File>)>,

    /// The state of the runtime when in unconstrained mode.
    pub unconstrained_state: Box<ForkState>,

    /// Statistics for event counts.
    pub local_counts: LocalCounts,

    /// Verifier used to sanity check `verify_sp1_proof` during runtime.
    pub subproof_verifier: Option<&'a dyn SubproofVerifier>,

    /// Registry of hooks, to be invoked by writing to certain file descriptors.
    pub hook_registry: HookRegistry<'a>,

    /// The maximal shapes for the program.
    pub maximal_shapes: Option<MaximalShapes>,

    /// The costs of the program.
    pub costs: HashMap<RiscvAirId, u64>,

    /// Skip deferred proof verification. This check is informational only, not related to circuit
    /// correctness.
    pub deferred_proof_verification: DeferredProofVerification,

    /// The frequency to check the stopping condition.
    pub shape_check_frequency: u64,

    /// Early exit if the estimate LDE size is too big.
    pub lde_size_check: bool,

    /// The maximum LDE size to allow.
    pub lde_size_threshold: u64,

    /// event counts for the current shard.
    pub event_counts: EnumMap<RiscvAirId, u64>,
}

/// The different modes the executor can run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum ExecutorMode {
    /// Run the execution with no tracing or checkpointing.
    Simple,
    /// Run the execution with checkpoints for memory.
    Checkpoint,
    /// Run the execution with full tracing of events.
    Trace,
    /// Run the execution with full tracing of events and size bounds for shape collection.
    ShapeCollection,
}

/// Information about event counts which are relevant for shape fixing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LocalCounts {
    /// The event counts.
    pub event_counts: Box<EnumMap<Opcode, u64>>,
    /// The number of syscalls sent globally in the current shard.
    pub syscalls_sent: usize,
    /// The number of addresses touched in this shard.
    pub local_mem: usize,
}

/// Errors that the [``Executor``] can throw.
#[derive(Error, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionError {
    /// The execution failed with a non-zero exit code.
    #[error("execution failed with exit code {0}")]
    HaltWithNonZeroExitCode(u32),

    /// The execution failed with an invalid memory access.
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u32),

    /// The execution failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The execution failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The execution failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The execution failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The execution failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),

    /// The program ended in unconstrained mode.
    #[error("program ended in unconstrained mode")]
    EndInUnconstrained(),
}

impl<'a> Executor<'a> {
    /// Create a new [``Executor``] from a program and options.
    #[must_use]
    pub fn new(program: Program, opts: SP1CoreOpts) -> Self {
        Self::with_context(program, opts, SP1Context::default())
    }

    /// Create a new runtime for the program, and setup the profiler if `TRACE_FILE` env var is set
    /// and the feature flag `profiling` is enabled.
    #[must_use]
    pub fn with_context_and_elf(
        opts: SP1CoreOpts,
        context: SP1Context<'a>,
        elf_bytes: &[u8],
    ) -> Self {
        let program = Program::from(elf_bytes).expect("Failed to create program from ELF bytes");

        #[cfg(not(feature = "profiling"))]
        return Self::with_context(program, opts, context);

        #[cfg(feature = "profiling")]
        {
            let mut this = Self::with_context(program, opts, context);

            let trace_buf = std::env::var("TRACE_FILE").ok().map(|file| {
                let file = File::create(file).unwrap();
                BufWriter::new(file)
            });

            if let Some(trace_buf) = trace_buf {
                eprintln!("Profiling enabled");

                let sample_rate = std::env::var("TRACE_SAMPLE_RATE")
                    .ok()
                    .and_then(|rate| {
                        eprintln!("Profiling sample rate: {rate}");
                        rate.parse::<u32>().ok()
                    })
                    .unwrap_or(1);

                this.profiler = Some((
                    Profiler::new(elf_bytes, sample_rate as u64)
                        .expect("Failed to create profiler"),
                    trace_buf,
                ));
            }

            this
        }
    }

    /// Create a new runtime from a program, options, and a context.
    ///
    /// Note: This function *will not* set up the profiler.
    #[must_use]
    pub fn with_context(program: Program, opts: SP1CoreOpts, context: SP1Context<'a>) -> Self {
        // Create a shared reference to the program.
        let program = Arc::new(program);

        // Create a default record with the program.
        let record = ExecutionRecord::new(program.clone());

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map();
        let max_syscall_cycles =
            syscall_map.values().map(|syscall| syscall.num_extra_cycles()).max().unwrap_or(0);

        let hook_registry = context.hook_registry.unwrap_or_default();

        let costs: HashMap<String, usize> =
            serde_json::from_str(include_str!("./artifacts/rv32im_costs.json")).unwrap();
        let costs: HashMap<RiscvAirId, usize> =
            costs.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v)).collect();

        Self {
            record: Box::new(record),
            records: vec![],
            state: ExecutionState::new(program.pc_start),
            program,
            memory_accesses: MemoryAccessRecord::default(),
            shard_size: (opts.shard_size as u32) * 4,
            shard_batch_size: opts.shard_batch_size as u32,
            cycle_tracker: HashMap::new(),
            io_buf: HashMap::new(),
            #[cfg(feature = "profiling")]
            profiler: None,
            unconstrained: false,
            unconstrained_state: Box::new(ForkState::default()),
            syscall_map,
            executor_mode: ExecutorMode::Trace,
            emit_global_memory_events: true,
            max_syscall_cycles,
            report: ExecutionReport::default(),
            local_counts: LocalCounts::default(),
            print_report: false,
            subproof_verifier: context.subproof_verifier,
            hook_registry,
            opts,
            max_cycles: context.max_cycles,
            deferred_proof_verification: context.deferred_proof_verification.into(),
            memory_checkpoint: Memory::default(),
            uninitialized_memory_checkpoint: Memory::default(),
            local_memory_access: HashMap::new(),
            maximal_shapes: None,
            costs: costs.into_iter().map(|(k, v)| (k, v as u64)).collect(),
            shape_check_frequency: 16,
            lde_size_check: false,
            lde_size_threshold: 0,
            event_counts: EnumMap::default(),
        }
    }

    /// Invokes a hook with the given file descriptor `fd` with the data `buf`.
    ///
    /// # Errors
    ///
    /// If the file descriptor is not found in the [``HookRegistry``], this function will return an
    /// error.
    pub fn hook(&self, fd: u32, buf: &[u8]) -> eyre::Result<Vec<Vec<u8>>> {
        Ok(self
            .hook_registry
            .get(fd)
            .ok_or(eyre::eyre!("no hook found for file descriptor {}", fd))?
            .invoke_hook(self.hook_env(), buf))
    }

    /// Prepare a `HookEnv` for use by hooks.
    #[must_use]
    pub fn hook_env<'b>(&'b self) -> HookEnv<'b, 'a> {
        HookEnv { runtime: self }
    }

    /// Recover runtime state from a program and existing execution state.
    #[must_use]
    pub fn recover(program: Program, state: ExecutionState, opts: SP1CoreOpts) -> Self {
        let mut runtime = Self::new(program, opts);
        runtime.state = state;
        // Disable deferred proof verification since we're recovering from a checkpoint, and the
        // checkpoint creator already had a chance to check the proofs.
        runtime.deferred_proof_verification = DeferredProofVerification::Disabled;
        runtime
    }

    /// Get the current values of the registers.
    #[allow(clippy::single_match_else)]
    #[must_use]
    pub fn registers(&mut self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let record = self.state.memory.registers.get(i);

            // Only add the previous memory state to checkpoint map if we're in checkpoint mode,
            // or if we're in unconstrained mode. In unconstrained mode, the mode is always
            // Simple.
            if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
                match record {
                    Some(record) => {
                        self.memory_checkpoint.registers.entry(i).or_insert_with(|| Some(*record));
                    }
                    None => {
                        self.memory_checkpoint.registers.entry(i).or_insert(None);
                    }
                }
            }

            registers[i as usize] = match record {
                Some(record) => record.value,
                None => 0,
            };
        }
        registers
    }

    /// Get the current value of a register.
    #[must_use]
    pub fn register(&mut self, register: Register) -> u32 {
        let addr = register as u32;
        let record = self.state.memory.registers.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }
        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a word.
    ///
    /// Assumes `addr` is a valid memory address, not a register.
    #[must_use]
    pub fn word(&mut self, addr: u32) -> u32 {
        #[allow(clippy::single_match_else)]
        let record = self.state.memory.page_table.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a byte.
    ///
    /// Assumes `addr` is a valid memory address, not a register.
    #[must_use]
    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    /// Get the current timestamp for a given memory access position.
    #[must_use]
    pub const fn timestamp(&self, position: &MemoryAccessPosition) -> u32 {
        self.state.clk + *position as u32
    }

    /// Get the current shard.
    #[must_use]
    #[inline]
    pub fn shard(&self) -> u32 {
        self.state.current_shard
    }

    /// Read a word from memory and create an access record.
    pub fn mr(
        &mut self,
        addr: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        // Check that the memory address is within the babybear field and not within the registers'
        // address space.  Also check that the address is aligned.
        if addr % 4 != 0 || addr <= Register::X31 as u32 || addr >= BABYBEAR_PRIME {
            panic!("Invalid memory access: addr={addr}");
        }

        // Get the memory record entry.
        let entry = self.state.memory.page_table.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.page_table.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.page_table.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .page_table
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        // We update the local memory counter in two cases:
        //  1. This is the first time the address is touched, this corresponds to the
        //     condition record.shard != shard.
        //  2. The address is being accessed in a syscall. In this case, we need to send it. We use
        //     local_memory_access to detect this. *WARNING*: This means that we are counting
        //     on the .is_some() condition to be true only in the SyscallContext.
        if !self.unconstrained && (record.shard != shard || local_memory_access.is_some()) {
            self.local_counts.local_mem += 1;
        }

        let prev_record = *record;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory read record.
        MemoryReadRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Read a register and return its value.
    ///
    /// Assumes that the executor mode IS NOT [`ExecutorMode::Trace`]
    pub fn rr(&mut self, register: Register, shard: u32, timestamp: u32) -> u32 {
        // Get the memory record entry.
        let addr = register as u32;
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        record.shard = shard;
        record.timestamp = timestamp;
        record.value
    }

    /// Read a register and create an access record.
    ///
    /// Assumes that self.mode IS [`ExecutorMode::Trace`].
    pub fn rr_traced(
        &mut self,
        register: Register,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        // Get the memory record entry.
        let addr = register as u32;
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }
        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }
        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };
        let prev_record = *record;
        record.shard = shard;
        record.timestamp = timestamp;
        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };
            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }
        // Construct the memory read record.
        MemoryReadRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.shard,
            prev_record.timestamp,
        )
    }
    /// Write a word to memory and create an access record.
    pub fn mw(
        &mut self,
        addr: u32,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        // Check that the memory address is within the babybear field and not within the registers'
        // address space.  Also check that the address is aligned.
        if addr % 4 != 0 || addr <= Register::X31 as u32 || addr >= BABYBEAR_PRIME {
            panic!("Invalid memory access: addr={addr}");
        }

        // Get the memory record entry.
        let entry = self.state.memory.page_table.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.page_table.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert(None);
                }
            }
        }
        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }
        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.page_table.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .page_table
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        // We update the local memory counter in two cases:
        //  1. This is the first time the address is touched, this corresponds to the
        //     condition record.shard != shard.
        //  2. The address is being accessed in a syscall. In this case, we need to send it. We use
        //     local_memory_access to detect this. *WARNING*: This means that we are counting
        //     on the .is_some() condition to be true only in the SyscallContext.
        if !self.unconstrained && (record.shard != shard || local_memory_access.is_some()) {
            self.local_counts.local_mem += 1;
        }

        let prev_record = *record;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;
        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory write record.
        MemoryWriteRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.value,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Write a word to a register and create an access record.
    ///
    /// Assumes that self.mode IS [`ExecutorMode::Trace`].
    pub fn rw_traced(
        &mut self,
        register: Register,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        let addr = register as u32;

        // Get the memory record entry.
        let entry = self.state.memory.registers.entry(addr);
        if self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this register, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        let prev_record = *record;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory write record.
        MemoryWriteRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.value,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Write a word to a register and create an access record.
    ///
    /// Assumes that the executor mode IS NOT [`ExecutorMode::Trace`].
    #[inline]
    pub fn rw(&mut self, register: Register, value: u32, shard: u32, timestamp: u32) {
        let addr = register as u32;
        // Get the memory record entry.
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this register, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;
    }

    /// Read from memory, assuming that all addresses are aligned.
    #[inline]
    pub fn mr_cpu(&mut self, addr: u32) -> u32 {
        // Read the address from memory and create a memory read record.
        let record =
            self.mr(addr, self.shard(), self.timestamp(&MemoryAccessPosition::Memory), None);
        // If we're not in unconstrained mode, record the access for the current cycle.
        if self.executor_mode == ExecutorMode::Trace {
            self.memory_accesses.memory = Some(record.into());
        }
        record.value
    }

    /// Read a register.
    #[inline]
    pub fn rr_cpu(&mut self, register: Register, position: MemoryAccessPosition) -> u32 {
        // Read the address from memory and create a memory read record if in trace mode.
        if self.executor_mode == ExecutorMode::Trace {
            let record = self.rr_traced(register, self.shard(), self.timestamp(&position), None);
            if !self.unconstrained {
                match position {
                    MemoryAccessPosition::A => self.memory_accesses.a = Some(record.into()),
                    MemoryAccessPosition::B => self.memory_accesses.b = Some(record.into()),
                    MemoryAccessPosition::C => self.memory_accesses.c = Some(record.into()),
                    MemoryAccessPosition::Memory => {
                        self.memory_accesses.memory = Some(record.into());
                    }
                }
            }
            record.value
        } else {
            self.rr(register, self.shard(), self.timestamp(&position))
        }
    }

    /// Write to memory.
    ///
    /// # Panics
    ///
    /// This function will panic if the address is not aligned or if the memory accesses are already
    /// initialized.
    pub fn mw_cpu(&mut self, addr: u32, value: u32) {
        // Read the address from memory and create a memory read record.
        let record =
            self.mw(addr, value, self.shard(), self.timestamp(&MemoryAccessPosition::Memory), None);
        // If we're not in unconstrained mode, record the access for the current cycle.
        if self.executor_mode == ExecutorMode::Trace {
            debug_assert!(self.memory_accesses.memory.is_none());
            self.memory_accesses.memory = Some(record.into());
        }
    }

    /// Write to a register.
    pub fn rw_cpu(&mut self, register: Register, value: u32) {
        // The only time we are writing to a register is when it is in operand A.
        let position = MemoryAccessPosition::A;

        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        let value = if register == Register::X0 { 0 } else { value };

        // Read the address from memory and create a memory read record.
        if self.executor_mode == ExecutorMode::Trace {
            let record =
                self.rw_traced(register, value, self.shard(), self.timestamp(&position), None);
            if !self.unconstrained {
                // The only time we are writing to a register is when it is in operand A.
                debug_assert!(self.memory_accesses.a.is_none());
                self.memory_accesses.a = Some(record.into());
            }
        } else {
            self.rw(register, value, self.shard(), self.timestamp(&position));
        }
    }

    /// Emit events for this cycle.
    #[allow(clippy::too_many_arguments)]
    fn emit_events(
        &mut self,
        clk: u32,
        next_pc: u32,
        instruction: &Instruction,
        syscall_code: SyscallCode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
        record: MemoryAccessRecord,
        exit_code: u32,
    ) {
        self.emit_cpu(clk, next_pc, a, b, c, record, exit_code);

        if instruction.is_alu_instruction() {
            self.emit_alu_event(instruction.opcode, a, b, c, op_a_0);
        } else if instruction.is_memory_load_instruction()
            || instruction.is_memory_store_instruction()
        {
            self.emit_mem_instr_event(instruction.opcode, a, b, c, op_a_0);
        } else if instruction.is_branch_instruction() {
            self.emit_branch_event(instruction.opcode, a, b, c, op_a_0, next_pc);
        } else if instruction.is_jump_instruction() {
            self.emit_jump_event(instruction.opcode, a, b, c, op_a_0, next_pc);
        } else if instruction.is_auipc_instruction() {
            self.emit_auipc_event(instruction.opcode, a, b, c, op_a_0);
        } else if instruction.is_ecall_instruction() {
            self.emit_syscall_event(clk, record.a, op_a_0, syscall_code, b, c, next_pc);
        } else {
            unreachable!()
        }
    }

    /// Emit a CPU event.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn emit_cpu(
        &mut self,
        clk: u32,
        next_pc: u32,
        a: u32,
        b: u32,
        c: u32,
        record: MemoryAccessRecord,
        exit_code: u32,
    ) {
        self.record.cpu_events.push(CpuEvent {
            clk,
            pc: self.state.pc,
            next_pc,
            a,
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            exit_code,
        });
    }

    /// Emit an ALU event.
    fn emit_alu_event(&mut self, opcode: Opcode, a: u32, b: u32, c: u32, op_a_0: bool) {
        let event = AluEvent { pc: self.state.pc, opcode, a, b, c, op_a_0 };
        match opcode {
            Opcode::ADD => {
                self.record.add_events.push(event);
            }
            Opcode::SUB => {
                self.record.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                self.record.bitwise_events.push(event);
            }
            Opcode::SLL => {
                self.record.shift_left_events.push(event);
            }
            Opcode::SRL | Opcode::SRA => {
                self.record.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.record.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH => {
                self.record.mul_events.push(event);
            }
            Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
                self.record.divrem_events.push(event);
                emit_divrem_dependencies(self, event);
            }
            _ => unreachable!(),
        }
    }

    /// Emit a memory instruction event.
    #[inline]
    fn emit_mem_instr_event(&mut self, opcode: Opcode, a: u32, b: u32, c: u32, op_a_0: bool) {
        let event = MemInstrEvent {
            shard: self.shard(),
            clk: self.state.clk,
            pc: self.state.pc,
            opcode,
            a,
            b,
            c,
            op_a_0,
            mem_access: self.memory_accesses.memory.expect("Must have memory access"),
        };

        self.record.memory_instr_events.push(event);
        emit_memory_dependencies(
            self,
            event,
            self.memory_accesses.memory.expect("Must have memory access").current_record(),
        );
    }

    /// Emit a branch event.
    #[inline]
    fn emit_branch_event(
        &mut self,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
        next_pc: u32,
    ) {
        let event = BranchEvent { pc: self.state.pc, next_pc, opcode, a, b, c, op_a_0 };
        self.record.branch_events.push(event);
        emit_branch_dependencies(self, event);
    }

    /// Emit a jump event.
    #[inline]
    fn emit_jump_event(
        &mut self,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
        next_pc: u32,
    ) {
        let event = JumpEvent::new(self.state.pc, next_pc, opcode, a, b, c, op_a_0);
        self.record.jump_events.push(event);
        emit_jump_dependencies(self, event);
    }

    /// Emit an AUIPC event.
    #[inline]
    fn emit_auipc_event(&mut self, opcode: Opcode, a: u32, b: u32, c: u32, op_a_0: bool) {
        let event = AUIPCEvent::new(self.state.pc, opcode, a, b, c, op_a_0);
        self.record.auipc_events.push(event);
        emit_auipc_dependency(self, event);
    }

    /// Create a syscall event.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub(crate) fn syscall_event(
        &self,
        clk: u32,
        a_record: Option<MemoryRecordEnum>,
        op_a_0: Option<bool>,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
        next_pc: u32,
    ) -> SyscallEvent {
        let (write, is_real) = match a_record {
            Some(MemoryRecordEnum::Write(record)) => (record, true),
            _ => (MemoryWriteRecord::default(), false),
        };

        // If op_a_0 is None, then we assume it is not register 0.  Note that this will happen
        // for syscall events that are created within the precompiles' execute function.  Those events will be
        // added to precompile tables, which wouldn't use the op_a_0 field.  Note that we can't make
        // the op_a_0 field an Option<bool> in SyscallEvent because of the cbindgen.
        let op_a_0 = op_a_0.unwrap_or(false);

        SyscallEvent {
            shard: self.shard(),
            clk,
            pc: self.state.pc,
            next_pc,
            a_record: write,
            a_record_is_real: is_real,
            op_a_0,
            syscall_code,
            syscall_id: syscall_code.syscall_id(),
            arg1,
            arg2,
        }
    }

    /// Emit a syscall event.
    #[allow(clippy::too_many_arguments)]
    fn emit_syscall_event(
        &mut self,
        clk: u32,
        a_record: Option<MemoryRecordEnum>,
        op_a_0: bool,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
        next_pc: u32,
    ) {
        let syscall_event =
            self.syscall_event(clk, a_record, Some(op_a_0), syscall_code, arg1, arg2, next_pc);

        self.record.syscall_events.push(syscall_event);
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction) -> (Register, u32, u32) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr_cpu(rs2, MemoryAccessPosition::C);
            let b = self.rr_cpu(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr_cpu(rs1, MemoryAccessPosition::B), imm);
            (rd, b, c)
        } else {
            debug_assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) =
                (Register::from_u8(instruction.op_a), instruction.op_b, instruction.op_c);
            (rd, b, c)
        }
    }

    /// Set the destination register with the result.
    #[inline]
    fn alu_rw(&mut self, rd: Register, a: u32) {
        self.rw_cpu(rd, a);
    }

    /// Fetch the input operand values for a load instruction.
    fn load_rr(&mut self, instruction: &Instruction) -> (Register, u32, u32, u32, u32) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr_cpu(rs1, MemoryAccessPosition::B), imm);
        let addr = b.wrapping_add(c);
        let memory_value = self.mr_cpu(align(addr));
        (rd, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a store instruction.
    fn store_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.s_type();
        let c = imm;
        let b = self.rr_cpu(rs2, MemoryAccessPosition::B);
        let a = self.rr_cpu(rs1, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        let memory_value = self.word(align(addr));
        (a, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.b_type();
        let c = imm;
        let b = self.rr_cpu(rs2, MemoryAccessPosition::B);
        let a = self.rr_cpu(rs1, MemoryAccessPosition::A);
        (a, b, c)
    }

    /// Fetch the instruction at the current program counter.
    #[inline]
    fn fetch(&self) -> Instruction {
        *self.program.fetch(self.state.pc)
    }

    /// Execute the given instruction over the current state of the runtime.
    #[allow(clippy::too_many_lines)]
    fn execute_instruction(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        // The `clk` variable contains the cycle before the current instruction is executed.  The
        // `state.clk` can be updated before the end of this function by precompiles' execution.
        let mut clk = self.state.clk;
        let mut exit_code = 0u32;
        let mut next_pc = self.state.pc.wrapping_add(4);
        // Will be set to a non-default value if the instruction is a syscall.

        let (mut a, b, c): (u32, u32, u32);

        if self.executor_mode == ExecutorMode::Trace {
            self.memory_accesses = MemoryAccessRecord::default();
        }

        // The syscall id for precompiles.  This is only used/set when opcode == ECALL.
        let mut syscall = SyscallCode::default();

        if !self.unconstrained {
            self.report.opcode_counts[instruction.opcode] += 1;
            self.local_counts.event_counts[instruction.opcode] += 1;
            if instruction.is_memory_load_instruction() {
                self.local_counts.event_counts[Opcode::ADD] += 2;
            } else if instruction.is_jump_instruction() {
                self.local_counts.event_counts[Opcode::ADD] += 1;
            } else if instruction.is_branch_instruction() {
                self.local_counts.event_counts[Opcode::ADD] += 1;
                self.local_counts.event_counts[Opcode::SLTU] += 2;
            } else if instruction.is_divrem_instruction() {
                self.local_counts.event_counts[Opcode::MUL] += 2;
                self.local_counts.event_counts[Opcode::ADD] += 2;
                self.local_counts.event_counts[Opcode::SLTU] += 1;
            }
        }

        if instruction.is_alu_instruction() {
            (a, b, c) = self.execute_alu(instruction);
        } else if instruction.is_memory_load_instruction() {
            (a, b, c) = self.execute_load(instruction)?;
        } else if instruction.is_memory_store_instruction() {
            (a, b, c) = self.execute_store(instruction)?;
        } else if instruction.is_branch_instruction() {
            (a, b, c, next_pc) = self.execute_branch(instruction, next_pc);
        } else if instruction.is_jump_instruction() {
            (a, b, c, next_pc) = self.execute_jump(instruction);
        } else if instruction.is_auipc_instruction() {
            let (rd, imm) = instruction.u_type();
            (b, c) = (imm, imm);
            a = self.state.pc.wrapping_add(b);
            self.rw_cpu(rd, a);
        } else if instruction.is_ecall_instruction() {
            (a, b, c, clk, next_pc, syscall, exit_code) = self.execute_ecall()?;
        } else if instruction.is_ebreak_instruction() {
            return Err(ExecutionError::Breakpoint());
        } else if instruction.is_unimp_instruction() {
            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
            return Err(ExecutionError::Unimplemented());
        } else {
            eprintln!("unreachable: {:?}", instruction.opcode);
            unreachable!()
        }

        // If the destination register is x0, then we need to make sure that a's value is 0.
        let op_a_0 = instruction.op_a == Register::X0 as u8;
        if op_a_0 {
            a = 0;
        }

        // Emit the events for this cycle.
        if self.executor_mode == ExecutorMode::Trace {
            self.emit_events(
                clk,
                next_pc,
                instruction,
                syscall,
                a,
                b,
                c,
                op_a_0,
                self.memory_accesses,
                exit_code,
            );
        };

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        Ok(())
    }

    /// Execute an ALU instruction.
    fn execute_alu(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, b, c) = self.alu_rr(instruction);
        let a = match instruction.opcode {
            Opcode::ADD => b.wrapping_add(c),
            Opcode::SUB => b.wrapping_sub(c),
            Opcode::XOR => b ^ c,
            Opcode::OR => b | c,
            Opcode::AND => b & c,
            Opcode::SLL => b.wrapping_shl(c),
            Opcode::SRL => b.wrapping_shr(c),
            Opcode::SRA => (b as i32).wrapping_shr(c) as u32,
            Opcode::SLT => {
                if (b as i32) < (c as i32) {
                    1
                } else {
                    0
                }
            }
            Opcode::SLTU => {
                if b < c {
                    1
                } else {
                    0
                }
            }
            Opcode::MUL => b.wrapping_mul(c),
            Opcode::MULH => (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32,
            Opcode::MULHU => ((b as u64).wrapping_mul(c as u64) >> 32) as u32,
            Opcode::MULHSU => (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32,
            Opcode::DIV => {
                if c == 0 {
                    u32::MAX
                } else {
                    (b as i32).wrapping_div(c as i32) as u32
                }
            }
            Opcode::DIVU => {
                if c == 0 {
                    u32::MAX
                } else {
                    b.wrapping_div(c)
                }
            }
            Opcode::REM => {
                if c == 0 {
                    b
                } else {
                    (b as i32).wrapping_rem(c as i32) as u32
                }
            }
            Opcode::REMU => {
                if c == 0 {
                    b
                } else {
                    b.wrapping_rem(c)
                }
            }
            _ => unreachable!(),
        };
        self.alu_rw(rd, a);
        (a, b, c)
    }

    /// Execute a load instruction.
    fn execute_load(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);

        let a = match instruction.opcode {
            Opcode::LB => ((memory_read_value >> ((addr % 4) * 8)) & 0xFF) as i8 as i32 as u32,
            Opcode::LH => {
                if addr % 2 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LH, addr));
                }
                ((memory_read_value >> (((addr / 2) % 2) * 16)) & 0xFFFF) as i16 as i32 as u32
            }
            Opcode::LW => {
                if addr % 4 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LW, addr));
                }
                memory_read_value
            }
            Opcode::LBU => (memory_read_value >> ((addr % 4) * 8)) & 0xFF,
            Opcode::LHU => {
                if addr % 2 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LHU, addr));
                }
                (memory_read_value >> (((addr / 2) % 2) * 16)) & 0xFFFF
            }
            _ => unreachable!(),
        };
        self.rw_cpu(rd, a);
        Ok((a, b, c))
    }

    /// Execute a store instruction.
    fn execute_store(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (a, b, c, addr, memory_read_value) = self.store_rr(instruction);

        let memory_store_value = match instruction.opcode {
            Opcode::SB => {
                let shift = (addr % 4) * 8;
                ((a & 0xFF) << shift) | (memory_read_value & !(0xFF << shift))
            }
            Opcode::SH => {
                if addr % 2 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let shift = ((addr / 2) % 2) * 16;
                ((a & 0xFFFF) << shift) | (memory_read_value & !(0xFFFF << shift))
            }
            Opcode::SW => {
                if addr % 4 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SW, addr));
                }
                a
            }
            _ => unreachable!(),
        };
        self.mw_cpu(align(addr), memory_store_value);
        Ok((a, b, c))
    }

    /// Execute a branch instruction.
    fn execute_branch(
        &mut self,
        instruction: &Instruction,
        mut next_pc: u32,
    ) -> (u32, u32, u32, u32) {
        let (a, b, c) = self.branch_rr(instruction);
        let branch = match instruction.opcode {
            Opcode::BEQ => a == b,
            Opcode::BNE => a != b,
            Opcode::BLT => (a as i32) < (b as i32),
            Opcode::BGE => (a as i32) >= (b as i32),
            Opcode::BLTU => a < b,
            Opcode::BGEU => a >= b,
            _ => {
                unreachable!()
            }
        };
        if branch {
            next_pc = self.state.pc.wrapping_add(c);
        }
        (a, b, c, next_pc)
    }

    /// Execute an ecall instruction.
    #[allow(clippy::type_complexity)]
    fn execute_ecall(
        &mut self,
    ) -> Result<(u32, u32, u32, u32, u32, SyscallCode, u32), ExecutionError> {
        // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
        // register is that we write to it later.
        let t0 = Register::X5;
        let syscall_id = self.register(t0);
        let c = self.rr_cpu(Register::X11, MemoryAccessPosition::C);
        let b = self.rr_cpu(Register::X10, MemoryAccessPosition::B);
        let syscall = SyscallCode::from_u32(syscall_id);

        if self.print_report && !self.unconstrained {
            self.report.syscall_counts[syscall] += 1;
        }

        // `hint_slice` is allowed in unconstrained mode since it is used to write the hint.
        // Other syscalls are not allowed because they can lead to non-deterministic
        // behavior, especially since many syscalls modify memory in place,
        // which is not permitted in unconstrained mode. This will result in
        // non-zero memory interactions when generating a proof.

        if self.unconstrained
            && (syscall != SyscallCode::EXIT_UNCONSTRAINED && syscall != SyscallCode::WRITE)
        {
            return Err(ExecutionError::InvalidSyscallUsage(syscall_id as u64));
        }

        // Update the syscall counts.
        let syscall_for_count = syscall.count_map();
        let syscall_count = self.state.syscall_counts.entry(syscall_for_count).or_insert(0);
        *syscall_count += 1;

        let syscall_impl = self.get_syscall(syscall).cloned();
        let mut precompile_rt = SyscallContext::new(self);
        let (a, precompile_next_pc, precompile_cycles, returned_exit_code) =
            if let Some(syscall_impl) = syscall_impl {
                // Executing a syscall optionally returns a value to write to the t0
                // register. If it returns None, we just keep the
                // syscall_id in t0.
                let res = syscall_impl.execute(&mut precompile_rt, syscall, b, c);
                let a = if let Some(val) = res { val } else { syscall_id };

                // If the syscall is `HALT` and the exit code is non-zero, return an error.
                if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
                    return Err(ExecutionError::HaltWithNonZeroExitCode(precompile_rt.exit_code));
                }

                (a, precompile_rt.next_pc, syscall_impl.num_extra_cycles(), precompile_rt.exit_code)
            } else {
                return Err(ExecutionError::UnsupportedSyscall(syscall_id));
            };

        // If the syscall is `EXIT_UNCONSTRAINED`, the memory was restored to pre-unconstrained code
        // in the execute function, so we need to re-read from x10 and x11.  Just do a peek on the
        // registers.
        let (b, c) = if syscall == SyscallCode::EXIT_UNCONSTRAINED {
            (self.register(Register::X10), self.register(Register::X11))
        } else {
            (b, c)
        };

        // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
        self.rw_cpu(t0, a);
        let clk = self.state.clk;
        self.state.clk += precompile_cycles;

        Ok((a, b, c, clk, precompile_next_pc, syscall, returned_exit_code))
    }

    /// Execute a jump instruction.
    fn execute_jump(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (a, b, c, next_pc) = match instruction.opcode {
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                let (b, c) = (imm, 0);
                let a = self.state.pc + 4;
                self.rw_cpu(rd, a);
                let next_pc = self.state.pc.wrapping_add(imm);
                (a, b, c, next_pc)
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr_cpu(rs1, MemoryAccessPosition::B), imm);
                let a = self.state.pc + 4;
                self.rw_cpu(rd, a);
                let next_pc = b.wrapping_add(c);
                (a, b, c, next_pc)
            }
            _ => unreachable!(),
        };
        (a, b, c, next_pc)
    }

    /// Executes one cycle of the program, returning whether the program has finished.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn execute_cycle(&mut self) -> Result<bool, ExecutionError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.fetch();

        // Log the current state of the runtime.
        self.log(&instruction);

        // Execute the instruction.
        self.execute_instruction(&instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        if !self.unconstrained {
            // If there's not enough cycles left for another instruction, move to the next shard.
            let cpu_exit = self.max_syscall_cycles + self.state.clk >= self.shard_size;

            // Every N cycles, check if there exists at least one shape that fits.
            //
            // If we're close to not fitting, early stop the shard to ensure we don't OOM.
            let mut shape_match_found = true;
            if self.state.global_clk % self.shape_check_frequency == 0 {
                // Estimate the number of events in the trace.
                self.estimate_riscv_event_counts(
                    (self.state.clk >> 2) as u64,
                    self.local_counts.local_mem as u64,
                    self.local_counts.syscalls_sent as u64,
                    *self.local_counts.event_counts,
                );

                // Check if the LDE size is too large.
                if self.lde_size_check {
                    let padded_event_counts =
                        pad_rv32im_event_counts(self.event_counts, self.shape_check_frequency);
                    let padded_lde_size = estimate_riscv_lde_size(padded_event_counts, &self.costs);
                    if padded_lde_size > self.lde_size_threshold {
                        tracing::warn!(
                            "stopping shard early due to lde size: {} gb",
                            (padded_lde_size as u64) / 1_000_000_000
                        );
                        shape_match_found = false;
                    }
                }
                // Check if we're too "close" to a maximal shape.
                else if let Some(maximal_shapes) = &self.maximal_shapes {
                    let distance = |threshold: usize, count: usize| {
                        (count != 0).then(|| threshold - count).unwrap_or(usize::MAX)
                    };

                    shape_match_found = false;

                    for shape in maximal_shapes.iter() {
                        let cpu_threshold = shape[CoreAirId::Cpu];
                        if self.state.clk > ((1 << cpu_threshold) << 2) {
                            continue;
                        }

                        let mut l_infinity = usize::MAX;
                        let mut shape_too_small = false;
                        for air in CoreAirId::iter() {
                            if air == CoreAirId::Cpu {
                                continue;
                            }

                            let threshold = 1 << shape[air];
                            let count = self.event_counts[RiscvAirId::from(air)] as usize;
                            if count > threshold {
                                shape_too_small = true;
                                break;
                            }

                            if distance(threshold, count) < l_infinity {
                                l_infinity = distance(threshold, count);
                            }
                        }

                        if shape_too_small {
                            continue;
                        }

                        if l_infinity >= 32 * (self.shape_check_frequency as usize) {
                            shape_match_found = true;
                            break;
                        }
                    }

                    if !shape_match_found {
                        self.record.counts = Some(self.event_counts);
                        log::warn!(
                            "stopping shard early due to no shapes fitting: \
                            clk: {},
                            clk_usage: {}",
                            (self.state.clk / 4).next_power_of_two().ilog2(),
                            ((self.state.clk / 4) as f64).log2(),
                        );
                    }
                }
            }

            if cpu_exit || !shape_match_found {
                self.state.current_shard += 1;
                self.state.clk = 0;
                self.bump_record();
            }
        }

        // If the cycle limit is exceeded, return an error.
        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
                return Err(ExecutionError::ExceededCycleLimit(max_cycles));
            }
        }

        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u32;
        if done && self.unconstrained {
            log::error!("program ended in unconstrained mode at clk {}", self.state.global_clk);
            return Err(ExecutionError::EndInUnconstrained());
        }
        Ok(done)
    }

    /// Bump the record.
    pub fn bump_record(&mut self) {
        self.local_counts = LocalCounts::default();
        // Copy all of the existing local memory accesses to the record's local_memory_access vec.
        if self.executor_mode == ExecutorMode::Trace {
            for (_, event) in self.local_memory_access.drain() {
                self.record.cpu_local_memory_access.push(event);
            }
        }

        let removed_record = std::mem::replace(
            &mut self.record,
            Box::new(ExecutionRecord::new(self.program.clone())),
        );
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.records.push(removed_record);
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the events emitted and whether the
    /// program ended.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_record(
        &mut self,
        emit_global_memory_events: bool,
    ) -> Result<(Vec<Box<ExecutionRecord>>, bool), ExecutionError> {
        self.executor_mode = ExecutorMode::Trace;
        self.emit_global_memory_events = emit_global_memory_events;
        self.print_report = true;
        let done = self.execute()?;
        Ok((std::mem::take(&mut self.records), done))
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the checkpoint from before execution
    /// and whether the program ended.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_state(
        &mut self,
        emit_global_memory_events: bool,
    ) -> Result<(ExecutionState, PublicValues<u32, u32>, bool), ExecutionError> {
        self.memory_checkpoint.clear();
        self.executor_mode = ExecutorMode::Checkpoint;
        self.emit_global_memory_events = emit_global_memory_events;

        // Clone self.state without memory, uninitialized_memory, proof_stream in it so it's faster.
        let memory = std::mem::take(&mut self.state.memory);
        let uninitialized_memory = std::mem::take(&mut self.state.uninitialized_memory);
        let proof_stream = std::mem::take(&mut self.state.proof_stream);
        let mut checkpoint = tracing::debug_span!("clone").in_scope(|| self.state.clone());
        self.state.memory = memory;
        self.state.uninitialized_memory = uninitialized_memory;
        self.state.proof_stream = proof_stream;

        let done = tracing::debug_span!("execute").in_scope(|| self.execute())?;
        // Create a checkpoint using `memory_checkpoint`. Just include all memory if `done` since we
        // need it all for MemoryFinalize.
        let next_pc = self.state.pc;
        tracing::debug_span!("create memory checkpoint").in_scope(|| {
            let replacement_memory_checkpoint = Memory::<_>::new_preallocated();
            let replacement_uninitialized_memory_checkpoint = Memory::<_>::new_preallocated();
            let memory_checkpoint =
                std::mem::replace(&mut self.memory_checkpoint, replacement_memory_checkpoint);
            let uninitialized_memory_checkpoint = std::mem::replace(
                &mut self.uninitialized_memory_checkpoint,
                replacement_uninitialized_memory_checkpoint,
            );
            if done && !self.emit_global_memory_events {
                // If it's the last shard, and we're not emitting memory events, we need to include
                // all memory so that memory events can be emitted from the checkpoint. But we need
                // to first reset any modified memory to as it was before the execution.
                checkpoint.memory.clone_from(&self.state.memory);
                memory_checkpoint.into_iter().for_each(|(addr, record)| {
                    if let Some(record) = record {
                        checkpoint.memory.insert(addr, record);
                    } else {
                        checkpoint.memory.remove(addr);
                    }
                });
                checkpoint.uninitialized_memory = self.state.uninitialized_memory.clone();
                // Remove memory that was written to in this batch.
                for (addr, is_old) in uninitialized_memory_checkpoint {
                    if !is_old {
                        checkpoint.uninitialized_memory.remove(addr);
                    }
                }
            } else {
                checkpoint.memory = memory_checkpoint
                    .into_iter()
                    .filter_map(|(addr, record)| record.map(|record| (addr, record)))
                    .collect();
                checkpoint.uninitialized_memory = uninitialized_memory_checkpoint
                    .into_iter()
                    .filter(|&(_, has_value)| has_value)
                    .map(|(addr, _)| (addr, *self.state.uninitialized_memory.get(addr).unwrap()))
                    .collect();
            }
        });
        let mut public_values = self.records.last().as_ref().unwrap().public_values;
        public_values.start_pc = next_pc;
        public_values.next_pc = next_pc;
        if !done {
            self.records.clear();
        }
        Ok((checkpoint, public_values, done))
    }

    fn initialize(&mut self) {
        self.state.clk = 0;

        tracing::debug!("loading memory image");
        for (&addr, value) in &self.program.memory_image {
            self.state.memory.insert(addr, MemoryRecord { value: *value, shard: 0, timestamp: 0 });
        }
    }

    /// Executes the program without tracing and without emitting events.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run_fast(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = true;
        while !self.execute()? {}

        #[cfg(feature = "profiling")]
        if let Some((profiler, writer)) = self.profiler.take() {
            profiler.write(writer).expect("Failed to write profile to output file");
        }

        Ok(())
    }

    /// Executes the program in checkpoint mode, without emitting the checkpoints.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run_checkpoint(
        &mut self,
        emit_global_memory_events: bool,
    ) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = true;
        while !self.execute_state(emit_global_memory_events)?.2 {}
        Ok(())
    }

    /// Executes the program and prints the execution report.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Trace;
        self.print_report = true;
        while !self.execute()? {}

        #[cfg(feature = "profiling")]
        if let Some((profiler, writer)) = self.profiler.take() {
            profiler.write(writer).expect("Failed to write profile to output file");
        }

        Ok(())
    }

    /// Executes up to `self.shard_batch_size` cycles of the program, returning whether the program
    /// has finished.
    pub fn execute(&mut self) -> Result<bool, ExecutionError> {
        // Get the program.
        let program = self.program.clone();

        // Get the current shard.
        let start_shard = self.state.current_shard;

        // If it's the first cycle, initialize the program.
        if self.state.global_clk == 0 {
            self.initialize();
        }

        // Loop until we've executed `self.shard_batch_size` shards if `self.shard_batch_size` is
        // set.
        let mut done = false;
        let mut current_shard = self.state.current_shard;
        let mut num_shards_executed = 0;
        loop {
            if self.execute_cycle()? {
                done = true;
                break;
            }

            if self.shard_batch_size > 0 && current_shard != self.state.current_shard {
                num_shards_executed += 1;
                current_shard = self.state.current_shard;
                if num_shards_executed == self.shard_batch_size {
                    break;
                }
            }
        }

        // Get the final public values.
        let public_values = self.record.public_values;

        if done {
            self.postprocess();

            // Push the remaining execution record with memory initialize & finalize events.
            self.bump_record();
        }

        // Push the remaining execution record, if there are any CPU events.
        if !self.record.cpu_events.is_empty() {
            self.bump_record();
        }

        // Set the global public values for all shards.
        let mut last_next_pc = 0;
        let mut last_exit_code = 0;
        for (i, record) in self.records.iter_mut().enumerate() {
            record.program = program.clone();
            record.public_values = public_values;
            record.public_values.committed_value_digest = public_values.committed_value_digest;
            record.public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            record.public_values.execution_shard = start_shard + i as u32;
            if record.cpu_events.is_empty() {
                record.public_values.start_pc = last_next_pc;
                record.public_values.next_pc = last_next_pc;
                record.public_values.exit_code = last_exit_code;
            } else {
                record.public_values.start_pc = record.cpu_events[0].pc;
                record.public_values.next_pc = record.cpu_events.last().unwrap().next_pc;
                record.public_values.exit_code = record.cpu_events.last().unwrap().exit_code;
                last_next_pc = record.public_values.next_pc;
                last_exit_code = record.public_values.exit_code;
            }
        }

        Ok(done)
    }

    fn postprocess(&mut self) {
        // Flush remaining stdout/stderr
        for (fd, buf) in &self.io_buf {
            if !buf.is_empty() {
                match fd {
                    1 => {
                        eprintln!("stdout: {buf}");
                    }
                    2 => {
                        eprintln!("stderr: {buf}");
                    }
                    _ => {}
                }
            }
        }

        // Ensure that all proofs and input bytes were read, otherwise warn the user.
        if self.state.proof_stream_ptr != self.state.proof_stream.len() {
            tracing::warn!(
                "Not all proofs were read. Proving will fail during recursion. Did you pass too
        many proofs in or forget to call verify_sp1_proof?"
            );
        }

        if !self.state.input_stream.is_empty() {
            tracing::warn!("Not all input bytes were read.");
        }

        if self.emit_global_memory_events
            && (self.executor_mode == ExecutorMode::Trace
                || self.executor_mode == ExecutorMode::Checkpoint)
        {
            // SECTION: Set up all MemoryInitializeFinalizeEvents needed for memory argument.
            let memory_finalize_events = &mut self.record.global_memory_finalize_events;
            memory_finalize_events.reserve_exact(self.state.memory.page_table.estimate_len() + 32);

            // We handle the addr = 0 case separately, as we constrain it to be 0 in the first row
            // of the memory finalize table so it must be first in the array of events.
            let addr_0_record = self.state.memory.get(0);

            let addr_0_final_record = match addr_0_record {
                Some(record) => record,
                None => &MemoryRecord { value: 0, shard: 0, timestamp: 1 },
            };
            memory_finalize_events
                .push(MemoryInitializeFinalizeEvent::finalize_from_record(0, addr_0_final_record));

            let memory_initialize_events = &mut self.record.global_memory_initialize_events;
            memory_initialize_events
                .reserve_exact(self.state.memory.page_table.estimate_len() + 32);
            let addr_0_initialize_event =
                MemoryInitializeFinalizeEvent::initialize(0, 0, addr_0_record.is_some());
            memory_initialize_events.push(addr_0_initialize_event);

            // Count the number of touched memory addresses manually, since `PagedMemory` doesn't
            // already know its length.
            self.report.touched_memory_addresses = 0;
            for addr in 1..32 {
                let record = self.state.memory.registers.get(addr);
                if record.is_some() {
                    self.report.touched_memory_addresses += 1;

                    // Program memory is initialized in the MemoryProgram chip and doesn't require any
                    // events, so we only send init events for other memory addresses.
                    if !self.record.program.memory_image.contains_key(&addr) {
                        let initial_value =
                            self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                        memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                            addr,
                            *initial_value,
                            true,
                        ));
                    }

                    let record = *record.unwrap();
                    memory_finalize_events
                        .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, &record));
                }
            }
            for addr in self.state.memory.page_table.keys() {
                self.report.touched_memory_addresses += 1;

                // Program memory is initialized in the MemoryProgram chip and doesn't require any
                // events, so we only send init events for other memory addresses.
                if !self.record.program.memory_image.contains_key(&addr) {
                    let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                    memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                        addr,
                        *initial_value,
                        true,
                    ));
                }

                let record = *self.state.memory.get(addr).unwrap();
                memory_finalize_events
                    .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, &record));
            }
        }
    }

    fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    /// Maps the opcode counts to the number of events in each air.
    pub fn estimate_riscv_event_counts(
        &mut self,
        cpu_cycles: u64,
        touched_addresses: u64,
        syscalls_sent: u64,
        opcode_counts: EnumMap<Opcode, u64>,
    ) {
        // Compute the number of events in the cpu chip.
        self.event_counts[RiscvAirId::Cpu] = cpu_cycles;

        // Compute the number of events in the add sub chip.
        self.event_counts[RiscvAirId::AddSub] =
            opcode_counts[Opcode::ADD] + opcode_counts[Opcode::SUB];

        // Compute the number of events in the mul chip.
        self.event_counts[RiscvAirId::Mul] = opcode_counts[Opcode::MUL]
            + opcode_counts[Opcode::MULH]
            + opcode_counts[Opcode::MULHU]
            + opcode_counts[Opcode::MULHSU];

        // Compute the number of events in the bitwise chip.
        self.event_counts[RiscvAirId::Bitwise] =
            opcode_counts[Opcode::XOR] + opcode_counts[Opcode::OR] + opcode_counts[Opcode::AND];

        // Compute the number of events in the shift left chip.
        self.event_counts[RiscvAirId::ShiftLeft] = opcode_counts[Opcode::SLL];

        // Compute the number of events in the shift right chip.
        self.event_counts[RiscvAirId::ShiftRight] =
            opcode_counts[Opcode::SRL] + opcode_counts[Opcode::SRA];

        // Compute the number of events in the divrem chip.
        self.event_counts[RiscvAirId::DivRem] = opcode_counts[Opcode::DIV]
            + opcode_counts[Opcode::DIVU]
            + opcode_counts[Opcode::REM]
            + opcode_counts[Opcode::REMU];

        // Compute the number of events in the lt chip.
        self.event_counts[RiscvAirId::Lt] =
            opcode_counts[Opcode::SLT] + opcode_counts[Opcode::SLTU];

        // Compute the number of events in the memory local chip.
        self.event_counts[RiscvAirId::MemoryLocal] =
            touched_addresses.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC as u64);

        // Compute the number of events in the branch chip.
        self.event_counts[RiscvAirId::Branch] = opcode_counts[Opcode::BEQ]
            + opcode_counts[Opcode::BNE]
            + opcode_counts[Opcode::BLT]
            + opcode_counts[Opcode::BGE]
            + opcode_counts[Opcode::BLTU]
            + opcode_counts[Opcode::BGEU];

        // Compute the number of events in the jump chip.
        self.event_counts[RiscvAirId::Jump] =
            opcode_counts[Opcode::JAL] + opcode_counts[Opcode::JALR];

        // Compute the number of events in the auipc chip.
        self.event_counts[RiscvAirId::Auipc] = opcode_counts[Opcode::AUIPC]
            + opcode_counts[Opcode::UNIMP]
            + opcode_counts[Opcode::EBREAK];

        // Compute the number of events in the memory instruction chip.
        self.event_counts[RiscvAirId::MemoryInstrs] = opcode_counts[Opcode::LB]
            + opcode_counts[Opcode::LH]
            + opcode_counts[Opcode::LW]
            + opcode_counts[Opcode::LBU]
            + opcode_counts[Opcode::LHU]
            + opcode_counts[Opcode::SB]
            + opcode_counts[Opcode::SH]
            + opcode_counts[Opcode::SW];

        // Compute the number of events in the syscall instruction chip.
        self.event_counts[RiscvAirId::SyscallInstrs] = opcode_counts[Opcode::ECALL];

        // Compute the number of events in the syscall core chip.
        self.event_counts[RiscvAirId::SyscallCore] = syscalls_sent;

        // Compute the number of events in the global chip.
        self.event_counts[RiscvAirId::Global] =
            2 * touched_addresses + self.event_counts[RiscvAirId::SyscallInstrs];

        // Adjust for divrem dependencies.
        self.event_counts[RiscvAirId::Mul] += self.event_counts[RiscvAirId::DivRem];
        self.event_counts[RiscvAirId::Lt] += self.event_counts[RiscvAirId::DivRem];

        // Note: we ignore the additional dependencies for addsub, since they are accounted for in
        // the maximal shapes.
    }

    #[inline]
    fn log(&mut self, _: &Instruction) {
        #[cfg(feature = "profiling")]
        if let Some((ref mut profiler, _)) = self.profiler {
            if !self.unconstrained {
                profiler.record(self.state.global_clk, self.state.pc as u64);
            }
        }

        if !self.unconstrained && self.state.global_clk % 10_000_000 == 0 {
            log::info!("clk = {} pc = 0x{:x?}", self.state.global_clk, self.state.pc);
        }
    }
}

impl Default for ExecutorMode {
    fn default() -> Self {
        Self::Simple
    }
}

/// Aligns an address to the nearest word below or equal to it.
#[must_use]
pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

#[cfg(test)]
mod tests {

    use sp1_stark::SP1CoreOpts;
    use sp1_zkvm::syscalls::SHA_COMPRESS;

    use crate::programs::tests::{
        fibonacci_program, panic_program, secp256r1_add_program, secp256r1_double_program,
        simple_memory_program, simple_program, ssz_withdrawals_program, u256xu2048_mul_program,
    };

    use crate::Register;

    use super::{Executor, Instruction, Opcode, Program};

    fn _assert_send<T: Send>() {}

    /// Runtime needs to be Send so we can use it across async calls.
    fn _assert_runtime_is_send() {
        _assert_send::<Executor>();
    }

    #[test]
    fn test_simple_program_run() {
        let program = simple_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 42);
    }

    #[test]
    fn test_fibonacci_program_run() {
        let program = fibonacci_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_secp256r1_add_program_run() {
        let program = secp256r1_add_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_secp256r1_double_program_run() {
        let program = secp256r1_double_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_u256xu2048_mul() {
        let program = u256xu2048_mul_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_ssz_withdrawals_program_run() {
        let program = ssz_withdrawals_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_panic() {
        let program = panic_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_add() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 42);
    }

    #[test]
    fn test_sub() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 32);
    }

    #[test]
    fn test_xor() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::XOR, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 32);
    }

    #[test]
    fn test_or() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::OR, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());

        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 37);
    }

    #[test]
    fn test_and() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::AND, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 5);
    }

    #[test]
    fn test_sll() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 1184);
    }

    #[test]
    fn test_srl() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SRL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 1);
    }

    #[test]
    fn test_sra() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SRA, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 1);
    }

    #[test]
    fn test_slt() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLT, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_sltu() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLTU, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_addi() {
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 29, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 84);
    }

    #[test]
    fn test_addi_negative() {
        //     addi x29, x0, 5
        //     addi x30, x29, -1
        //     addi x31, x30, 4
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 29, 0xFFFF_FFFF, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 5 - 1 + 4);
    }

    #[test]
    fn test_xori() {
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::XOR, 30, 29, 37, false, true),
            Instruction::new(Opcode::XOR, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 10);
    }

    #[test]
    fn test_ori() {
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::OR, 30, 29, 37, false, true),
            Instruction::new(Opcode::OR, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 47);
    }

    #[test]
    fn test_andi() {
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::AND, 30, 29, 37, false, true),
            Instruction::new(Opcode::AND, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_slli() {
        //     addi x29, x0, 5
        //     slli x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::SLL, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 80);
    }

    #[test]
    fn test_srli() {
        //    addi x29, x0, 5
        //    srli x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SRL, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 2);
    }

    #[test]
    fn test_srai() {
        //   addi x29, x0, 5
        //   srai x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SRA, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 2);
    }

    #[test]
    fn test_slti() {
        //   addi x29, x0, 5
        //   slti x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SLT, 31, 29, 37, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_sltiu() {
        //   addi x29, x0, 5
        //   sltiu x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SLTU, 31, 29, 37, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_jalr() {
        //   addi x11, x11, 100
        //   jalr x5, x11, 8
        //
        // `JALR rd offset(rs)` reads the value at rs, adds offset to it and uses it as the
        // destination address. It then stores the address of the next instruction in rd in case
        // we'd want to come back here.

        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 11, 100, false, true),
            Instruction::new(Opcode::JALR, 5, 11, 8, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.registers()[Register::X5 as usize], 8);
        assert_eq!(runtime.registers()[Register::X11 as usize], 100);
        assert_eq!(runtime.state.pc, 108);
    }

    fn simple_op_code_test(opcode: Opcode, expected: u32, a: u32, b: u32) {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 10, 0, a, false, true),
            Instruction::new(Opcode::ADD, 11, 0, b, false, true),
            Instruction::new(opcode, 12, 10, 11, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.registers()[Register::X12 as usize], expected);
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn multiplication_tests() {
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff);

        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff);

        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MULH, 0x00010000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff);

        simple_op_code_test(Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7);
        simple_op_code_test(Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MUL, 0x00000001, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MUL, 0x00000015, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff);
    }

    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
    }

    #[test]
    fn division_tests() {
        simple_op_code_test(Opcode::DIVU, 3, 20, 6);
        simple_op_code_test(Opcode::DIVU, 715_827_879, u32::MAX - 20 + 1, 6);
        simple_op_code_test(Opcode::DIVU, 0, 20, u32::MAX - 6 + 1);
        simple_op_code_test(Opcode::DIVU, 0, u32::MAX - 20 + 1, u32::MAX - 6 + 1);

        simple_op_code_test(Opcode::DIVU, 1 << 31, 1 << 31, 1);
        simple_op_code_test(Opcode::DIVU, 0, 1 << 31, u32::MAX - 1 + 1);

        simple_op_code_test(Opcode::DIVU, u32::MAX, 1 << 31, 0);
        simple_op_code_test(Opcode::DIVU, u32::MAX, 1, 0);
        simple_op_code_test(Opcode::DIVU, u32::MAX, 0, 0);

        simple_op_code_test(Opcode::DIV, 3, 18, 6);
        simple_op_code_test(Opcode::DIV, neg(6), neg(24), 4);
        simple_op_code_test(Opcode::DIV, neg(2), 16, neg(8));
        simple_op_code_test(Opcode::DIV, neg(1), 0, 0);

        // Overflow cases
        simple_op_code_test(Opcode::DIV, 1 << 31, 1 << 31, neg(1));
        simple_op_code_test(Opcode::REM, 0, 1 << 31, neg(1));
    }

    #[test]
    fn remainder_tests() {
        simple_op_code_test(Opcode::REM, 7, 16, 9);
        simple_op_code_test(Opcode::REM, neg(4), neg(22), 6);
        simple_op_code_test(Opcode::REM, 1, 25, neg(3));
        simple_op_code_test(Opcode::REM, neg(2), neg(22), neg(4));
        simple_op_code_test(Opcode::REM, 0, 873, 1);
        simple_op_code_test(Opcode::REM, 0, 873, neg(1));
        simple_op_code_test(Opcode::REM, 5, 5, 0);
        simple_op_code_test(Opcode::REM, neg(5), neg(5), 0);
        simple_op_code_test(Opcode::REM, 0, 0, 0);

        simple_op_code_test(Opcode::REMU, 4, 18, 7);
        simple_op_code_test(Opcode::REMU, 6, neg(20), 11);
        simple_op_code_test(Opcode::REMU, 23, 23, neg(6));
        simple_op_code_test(Opcode::REMU, neg(21), neg(21), neg(11));
        simple_op_code_test(Opcode::REMU, 5, 5, 0);
        simple_op_code_test(Opcode::REMU, neg(1), neg(1), 0);
        simple_op_code_test(Opcode::REMU, 0, 0, 0);
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn shift_tests() {
        simple_op_code_test(Opcode::SLL, 0x00000001, 0x00000001, 0);
        simple_op_code_test(Opcode::SLL, 0x00000002, 0x00000001, 1);
        simple_op_code_test(Opcode::SLL, 0x00000080, 0x00000001, 7);
        simple_op_code_test(Opcode::SLL, 0x00004000, 0x00000001, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0x00000001, 31);
        simple_op_code_test(Opcode::SLL, 0xffffffff, 0xffffffff, 0);
        simple_op_code_test(Opcode::SLL, 0xfffffffe, 0xffffffff, 1);
        simple_op_code_test(Opcode::SLL, 0xffffff80, 0xffffffff, 7);
        simple_op_code_test(Opcode::SLL, 0xffffc000, 0xffffffff, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0xffffffff, 31);
        simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0);
        simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 1);
        simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 7);
        simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0x21212121, 31);
        simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0xffffffe0);
        simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 0xffffffe1);
        simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 0xffffffe7);
        simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 0xffffffee);
        simple_op_code_test(Opcode::SLL, 0x00000000, 0x21212120, 0xffffffff);

        simple_op_code_test(Opcode::SRL, 0xffff8000, 0xffff8000, 0);
        simple_op_code_test(Opcode::SRL, 0x7fffc000, 0xffff8000, 1);
        simple_op_code_test(Opcode::SRL, 0x01ffff00, 0xffff8000, 7);
        simple_op_code_test(Opcode::SRL, 0x0003fffe, 0xffff8000, 14);
        simple_op_code_test(Opcode::SRL, 0x0001ffff, 0xffff8001, 15);
        simple_op_code_test(Opcode::SRL, 0xffffffff, 0xffffffff, 0);
        simple_op_code_test(Opcode::SRL, 0x7fffffff, 0xffffffff, 1);
        simple_op_code_test(Opcode::SRL, 0x01ffffff, 0xffffffff, 7);
        simple_op_code_test(Opcode::SRL, 0x0003ffff, 0xffffffff, 14);
        simple_op_code_test(Opcode::SRL, 0x00000001, 0xffffffff, 31);
        simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0);
        simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 1);
        simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 7);
        simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 14);
        simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 31);
        simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0);
        simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1);
        simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7);
        simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee);
        simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff);

        simple_op_code_test(Opcode::SRA, 0x00000000, 0x00000000, 0);
        simple_op_code_test(Opcode::SRA, 0xc0000000, 0x80000000, 1);
        simple_op_code_test(Opcode::SRA, 0xff000000, 0x80000000, 7);
        simple_op_code_test(Opcode::SRA, 0xfffe0000, 0x80000000, 14);
        simple_op_code_test(Opcode::SRA, 0xffffffff, 0x80000001, 31);
        simple_op_code_test(Opcode::SRA, 0x7fffffff, 0x7fffffff, 0);
        simple_op_code_test(Opcode::SRA, 0x3fffffff, 0x7fffffff, 1);
        simple_op_code_test(Opcode::SRA, 0x00ffffff, 0x7fffffff, 7);
        simple_op_code_test(Opcode::SRA, 0x0001ffff, 0x7fffffff, 14);
        simple_op_code_test(Opcode::SRA, 0x00000000, 0x7fffffff, 31);
        simple_op_code_test(Opcode::SRA, 0x81818181, 0x81818181, 0);
        simple_op_code_test(Opcode::SRA, 0xc0c0c0c0, 0x81818181, 1);
        simple_op_code_test(Opcode::SRA, 0xff030303, 0x81818181, 7);
        simple_op_code_test(Opcode::SRA, 0xfffe0606, 0x81818181, 14);
        simple_op_code_test(Opcode::SRA, 0xffffffff, 0x81818181, 31);
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn test_simple_memory_program_run() {
        let program = simple_memory_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();

        // Assert SW & LW case
        assert_eq!(runtime.register(Register::X28), 0x12348765);

        // Assert LBU cases
        assert_eq!(runtime.register(Register::X27), 0x65);
        assert_eq!(runtime.register(Register::X26), 0x87);
        assert_eq!(runtime.register(Register::X25), 0x34);
        assert_eq!(runtime.register(Register::X24), 0x12);

        // Assert LB cases
        assert_eq!(runtime.register(Register::X23), 0x65);
        assert_eq!(runtime.register(Register::X22), 0xffffff87);

        // Assert LHU cases
        assert_eq!(runtime.register(Register::X21), 0x8765);
        assert_eq!(runtime.register(Register::X20), 0x1234);

        // Assert LH cases
        assert_eq!(runtime.register(Register::X19), 0xffff8765);
        assert_eq!(runtime.register(Register::X18), 0x1234);

        // Assert SB cases
        assert_eq!(runtime.register(Register::X16), 0x12348725);
        assert_eq!(runtime.register(Register::X15), 0x12342525);
        assert_eq!(runtime.register(Register::X14), 0x12252525);
        assert_eq!(runtime.register(Register::X13), 0x25252525);

        // Assert SH cases
        assert_eq!(runtime.register(Register::X12), 0x12346525);
        assert_eq!(runtime.register(Register::X11), 0x65256525);
    }

    #[test]
    #[should_panic]
    fn test_invalid_address_access_sw() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 20, false, true),
            Instruction::new(Opcode::SW, 0, 29, 0, false, true),
        ];

        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_invalid_address_access_lw() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 20, false, true),
            Instruction::new(Opcode::LW, 29, 29, 0, false, true),
        ];

        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_invalid_address_syscall() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, SHA_COMPRESS, false, true),
            Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
            Instruction::new(Opcode::ADD, 11, 10, 20, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ];

        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }
}
