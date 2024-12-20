use hashbrown::HashMap;
use itertools::{EitherOrBoth, Itertools};
use p3_field::{AbstractField, PrimeField};
use sp1_stark::{
    air::{MachineAir, PublicValues},
    MachineRecord, SP1CoreOpts, SplitOpts,
};
use std::{mem::take, sync::Arc};

use serde::{Deserialize, Serialize};

use super::{program::Program, Opcode};
use crate::{
    events::{
        add_sharded_byte_lookup_events, AluEvent, ByteLookupEvent, ByteRecord, CpuEvent, LookupId,
        MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryRecordEnum, PrecompileEvent,
        PrecompileEvents, SyscallEvent,
    },
    syscalls::SyscallCode,
    CoreShape,
};

/// A record of the execution of a program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub program: Arc<Program>,
    pub cpu_events: Vec<CpuEvent>,
    pub add_events: Vec<AluEvent>,
    pub mul_events: Vec<AluEvent>,
    pub sub_events: Vec<AluEvent>,
    pub bitwise_events: Vec<AluEvent>,
    pub shift_left_events: Vec<AluEvent>,
    pub shift_right_events: Vec<AluEvent>,
    pub divrem_events: Vec<AluEvent>,
    pub lt_events: Vec<AluEvent>,
    pub byte_lookups: HashMap<u32, HashMap<ByteLookupEvent, usize>>,
    pub precompile_events: PrecompileEvents,
    pub global_memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    pub global_memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    pub syscall_events: Vec<SyscallEvent>,
    pub public_values: PublicValues<u32, u32>,
    pub nonce_lookup: Vec<u32>,
    pub next_nonce: u64,
    pub shape: Option<CoreShape>,
}

impl Default for ExecutionRecord {
    fn default() -> Self {
        let mut res = Self {
            program: Arc::default(),
            cpu_events: Vec::default(),
            add_events: Vec::default(),
            mul_events: Vec::default(),
            sub_events: Vec::default(),
            bitwise_events: Vec::default(),
            shift_left_events: Vec::default(),
            shift_right_events: Vec::default(),
            divrem_events: Vec::default(),
            lt_events: Vec::default(),
            byte_lookups: HashMap::default(),
            precompile_events: PrecompileEvents::default(),
            global_memory_initialize_events: Vec::default(),
            global_memory_finalize_events: Vec::default(),
            cpu_local_memory_access: Vec::default(),
            syscall_events: Vec::default(),
            public_values: PublicValues::default(),
            nonce_lookup: Vec::default(),
            next_nonce: 0,
            shape: None,
        };
        res.nonce_lookup.insert(0, 0);
        res
    }
}

impl ExecutionRecord {
    pub fn new(program: Arc<Program>) -> Self {
        let mut res = Self { program, ..Default::default() };
        res.nonce_lookup.insert(0, 0);
        res
    }

    pub fn create_lookup_id(&mut self) -> LookupId {
        let id = self.next_nonce;
        self.next_nonce += 1;
        LookupId(id)
    }

    pub fn create_lookup_ids(&mut self) -> [LookupId; 6] {
        std::array::from_fn(|_| self.create_lookup_id())
    }

    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    pub fn add_alu_events(&mut self, alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for (opcode, value) in alu_events {
            let target_vec = match opcode {
                Opcode::ADD => &mut self.add_events,
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => &mut self.mul_events,
                Opcode::SUB => &mut self.sub_events,
                Opcode::XOR | Opcode::OR | Opcode::AND => &mut self.bitwise_events,
                Opcode::SLL => &mut self.shift_left_events,
                Opcode::SRL | Opcode::SRA => &mut self.shift_right_events,
                Opcode::SLT | Opcode::SLTU => &mut self.lt_events,
                _ => panic!("Invalid opcode: {opcode:?}"),
            };
            target_vec.append(&mut value);
        }
    }

    pub fn defer(&mut self) -> ExecutionRecord {
        let mut execution_record = ExecutionRecord::new(self.program.clone());
        execution_record.precompile_events = take(&mut self.precompile_events);
        execution_record.global_memory_initialize_events = take(&mut self.global_memory_initialize_events);
        execution_record.global_memory_finalize_events = take(&mut self.global_memory_finalize_events);
        execution_record
    }

    pub fn split(&mut self, last: bool, opts: SplitOpts) -> Vec<ExecutionRecord> {
        let mut shards = Vec::new();
        let precompile_events = take(&mut self.precompile_events);

        for (syscall_code, events) in precompile_events {
            let threshold = match syscall_code {
                SyscallCode::KECCAK_PERMUTE => opts.keccak,
                SyscallCode::SHA_EXTEND => opts.sha_extend,
                SyscallCode::SHA_COMPRESS => opts.sha_compress,
                _ => opts.deferred,
            };

            let chunks = events.chunks_exact(threshold);
            if last {
                let remainder = chunks.remainder().to_vec();
                if !remainder.is_empty() {
                    let mut execution_record = ExecutionRecord::new(self.program.clone());
                    execution_record.precompile_events.insert(syscall_code, remainder);
                    shards.push(execution_record);
                }
            } else {
                self.precompile_events.insert(syscall_code, chunks.remainder().to_vec());
            }

            let event_shards: Vec<_> = chunks
                .map(|chunk| {
                    let mut execution_record = ExecutionRecord::new(self.program.clone());
                    execution_record.precompile_events.insert(syscall_code, chunk.to_vec());
                    execution_record
                })
                .collect();
            shards.extend(event_shards);
        }

        if last {
            self.global_memory_initialize_events.sort_by_key(|event| event.addr);
            self.global_memory_finalize_events.sort_by_key(|event| event.addr);

            let mut init_addr_bits = [0; 32];
            let mut finalize_addr_bits = [0; 32];
            for mem_chunks in self.global_memory_initialize_events
                .chunks(opts.memory)
                .zip_longest(self.global_memory_finalize_events.chunks(opts.memory))
            {
                let (mem_init_chunk, mem_finalize_chunk) = match mem_chunks {
                    EitherOrBoth::Both(mem_init_chunk, mem_finalize_chunk) => {
                        (mem_init_chunk, mem_finalize_chunk)
                    }
                    EitherOrBoth::Left(mem_init_chunk) => (mem_init_chunk, &[]),
                    EitherOrBoth::Right(mem_finalize_chunk) => (&[], mem_finalize_chunk),
                };

                let mut shard = ExecutionRecord::new(self.program.clone());
                shard.global_memory_initialize_events.extend_from_slice(mem_init_chunk);
                shard.public_values.previous_init_addr_bits = init_addr_bits;
                if let Some(last_event) = mem_init_chunk.last() {
                    init_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                }
                shard.public_values.last_init_addr_bits = init_addr_bits;

                shard.global_memory_finalize_events.extend_from_slice(mem_finalize_chunk);
                shard.public_values.previous_finalize_addr_bits = finalize_addr_bits;
                if let Some(last_event) = mem_finalize_chunk.last() {
                    finalize_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                }
                shard.public_values.last_finalize_addr_bits = finalize_addr_bits;

                shards.push(shard);
            }
        }

        shards
    }

    pub fn fixed_log2_rows<F: PrimeField, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.shape
            .as_ref()
            .and_then(|shape| shape.inner.get(&air.name()))
            .copied()
    }

    pub fn contains_cpu(&self) -> bool {
        !self.cpu_events.is_empty()
    }

    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event
