use hashbrown::HashMap;
use std::sync::Arc;

use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

use super::program::Program;
use super::Opcode;
use super::SyscallCode;
use crate::air::PublicValues;
use crate::alu::AluEvent;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::runtime::MemoryInitializeFinalizeEvent;
use crate::runtime::MemoryRecordEnum;
use crate::stark::MachineRecord;
use crate::syscall::precompiles::edwards::EdDecompressEvent;
use crate::syscall::precompiles::keccak256::KeccakPermuteEvent;
use crate::syscall::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::syscall::precompiles::uint256::Uint256MulEvent;
use crate::syscall::precompiles::ECDecompressEvent;
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};
use crate::utils::SP1CoreOpts;

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,

    /// A trace of the MUL events.
    pub mul_events: Vec<AluEvent>,

    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,

    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,

    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,

    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,

    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,

    /// All byte lookups that are needed.
    ///
    /// The layout is shard -> (event -> count). Byte lookups are sharded to prevent the
    /// multiplicities from overflowing.
    pub byte_lookups: HashMap<u32, HashMap<ByteLookupEvent, usize>>,

    pub sha_extend_events: Vec<ShaExtendEvent>,

    pub sha_compress_events: Vec<ShaCompressEvent>,

    pub keccak_permute_events: Vec<KeccakPermuteEvent>,

    pub ed_add_events: Vec<ECAddEvent>,

    pub ed_decompress_events: Vec<EdDecompressEvent>,

    pub secp256k1_add_events: Vec<ECAddEvent>,

    pub secp256k1_double_events: Vec<ECDoubleEvent>,

    pub bn254_add_events: Vec<ECAddEvent>,

    pub bn254_double_events: Vec<ECDoubleEvent>,

    pub k256_decompress_events: Vec<ECDecompressEvent>,

    pub bls12381_add_events: Vec<ECAddEvent>,

    pub bls12381_double_events: Vec<ECDoubleEvent>,

    pub uint256_mul_events: Vec<Uint256MulEvent>,

    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,

    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,

    pub bls12381_decompress_events: Vec<ECDecompressEvent>,

    /// The public values.
    pub public_values: PublicValues<u32, u32>,

    pub nonce_lookup: HashMap<usize, u32>,
}

pub struct ShardingConfig {
    pub shard_size: usize,
    pub add_len: usize,
    pub mul_len: usize,
    pub sub_len: usize,
    pub bitwise_len: usize,
    pub shift_left_len: usize,
    pub shift_right_len: usize,
    pub divrem_len: usize,
    pub lt_len: usize,
    pub field_len: usize,
    pub mem_init_len: usize,
    pub mem_finalize_len: usize,
    pub keccak_len: usize,
    pub secp256k1_add_len: usize,
    pub secp256k1_double_len: usize,
    pub bn254_add_len: usize,
    pub bn254_double_len: usize,
    pub bls12381_add_len: usize,
    pub bls12381_double_len: usize,
    pub uint256_mul_len: usize,
}

impl ShardingConfig {
    pub const fn shard_size(&self) -> usize {
        self.shard_size
    }
}

impl Default for ShardingConfig {
    fn default() -> Self {
        let shard_size = SP1CoreOpts::default().shard_size;
        Self {
            shard_size,
            add_len: shard_size,
            sub_len: shard_size,
            bitwise_len: shard_size,
            shift_left_len: shard_size,
            divrem_len: shard_size,
            lt_len: shard_size,
            mul_len: shard_size,
            shift_right_len: shard_size,
            mem_init_len: shard_size,
            mem_finalize_len: shard_size,
            field_len: shard_size * 4,
            keccak_len: shard_size,
            secp256k1_add_len: shard_size,
            secp256k1_double_len: shard_size,
            bn254_add_len: shard_size,
            bn254_double_len: shard_size,
            bls12381_add_len: shard_size,
            bls12381_double_len: shard_size,
            uint256_mul_len: shard_size,
        }
    }
}

impl MachineRecord for ExecutionRecord {
    type Config = ShardingConfig;

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert("add_events".to_string(), self.add_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("sub_events".to_string(), self.sub_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert(
            "shift_left_events".to_string(),
            self.shift_left_events.len(),
        );
        stats.insert(
            "shift_right_events".to_string(),
            self.shift_right_events.len(),
        );
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert(
            "sha_extend_events".to_string(),
            self.sha_extend_events.len(),
        );
        stats.insert(
            "sha_compress_events".to_string(),
            self.sha_compress_events.len(),
        );
        stats.insert(
            "keccak_permute_events".to_string(),
            self.keccak_permute_events.len(),
        );
        stats.insert("ed_add_events".to_string(), self.ed_add_events.len());
        stats.insert(
            "ed_decompress_events".to_string(),
            self.ed_decompress_events.len(),
        );
        stats.insert(
            "secp256k1_add_events".to_string(),
            self.secp256k1_add_events.len(),
        );
        stats.insert(
            "secp256k1_double_events".to_string(),
            self.secp256k1_double_events.len(),
        );
        stats.insert("bn254_add_events".to_string(), self.bn254_add_events.len());
        stats.insert(
            "bn254_double_events".to_string(),
            self.bn254_double_events.len(),
        );
        stats.insert(
            "k256_decompress_events".to_string(),
            self.k256_decompress_events.len(),
        );
        stats.insert(
            "bls12381_add_events".to_string(),
            self.bls12381_add_events.len(),
        );
        stats.insert(
            "bls12381_double_events".to_string(),
            self.bls12381_double_events.len(),
        );
        stats.insert(
            "uint256_mul_events".to_string(),
            self.uint256_mul_events.len(),
        );
        stats.insert(
            "bls12381_decompress_events".to_string(),
            self.bls12381_decompress_events.len(),
        );
        stats.insert(
            "memory_initialize_events".to_string(),
            self.memory_initialize_events.len(),
        );
        stats.insert(
            "memory_finalize_events".to_string(),
            self.memory_finalize_events.len(),
        );
        if !self.cpu_events.is_empty() {
            let shard = self.cpu_events[0].shard;
            stats.insert(
                "byte_lookups".to_string(),
                self.byte_lookups.get(&shard).map_or(0, |v| v.len()),
            );
        }
        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_events.append(&mut other.cpu_events);
        self.add_events.append(&mut other.add_events);
        self.sub_events.append(&mut other.sub_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_right_events
            .append(&mut other.shift_right_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.sha_extend_events.append(&mut other.sha_extend_events);
        self.sha_compress_events
            .append(&mut other.sha_compress_events);
        self.keccak_permute_events
            .append(&mut other.keccak_permute_events);
        self.ed_add_events.append(&mut other.ed_add_events);
        self.ed_decompress_events
            .append(&mut other.ed_decompress_events);
        self.secp256k1_add_events
            .append(&mut other.secp256k1_add_events);
        self.secp256k1_double_events
            .append(&mut other.secp256k1_double_events);
        self.bn254_add_events.append(&mut other.bn254_add_events);
        self.bn254_double_events
            .append(&mut other.bn254_double_events);
        self.k256_decompress_events
            .append(&mut other.k256_decompress_events);
        self.bls12381_add_events
            .append(&mut other.bls12381_add_events);
        self.bls12381_double_events
            .append(&mut other.bls12381_double_events);
        self.uint256_mul_events
            .append(&mut other.uint256_mul_events);
        self.bls12381_decompress_events
            .append(&mut other.bls12381_decompress_events);

        // Merge the byte lookups.
        for (shard, events_map) in std::mem::take(&mut other.byte_lookups).into_iter() {
            match self.byte_lookups.get_mut(&shard) {
                Some(existing) => {
                    // If there's already a map for this shard, update counts for each event.
                    for (event, count) in events_map.iter() {
                        *existing.entry(*event).or_insert(0) += count;
                    }
                }
                None => {
                    // If there isn't a map for this shard, insert the whole map.
                    self.byte_lookups.insert(shard, events_map);
                }
            }
        }

        self.memory_initialize_events
            .append(&mut other.memory_initialize_events);
        self.memory_finalize_events
            .append(&mut other.memory_finalize_events);
    }

    fn register_nonces(&mut self, syscall_lookups: &mut HashMap<u32, usize>) {
        self.add_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        self.sub_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup
                .insert(event.lookup_id, (self.add_events.len() + i) as u32);
        });

        self.mul_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        self.bitwise_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.shift_left_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.shift_right_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.divrem_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.lt_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        let count = syscall_lookups
            .entry(SyscallCode::KECCAK_PERMUTE as u32)
            .or_insert(0);
        self.keccak_permute_events.iter().for_each(|event| {
            self.nonce_lookup.insert(
                event.lookup_id,
                ((*count % DEFERRED_SPLIT_THRESHOLD) * 24) as u32,
            );
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::SECP256K1_ADD as u32)
            .or_insert(0);
        self.secp256k1_add_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::SECP256K1_DOUBLE as u32)
            .or_insert(0);
        self.secp256k1_double_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::BN254_ADD as u32)
            .or_insert(0);
        self.bn254_add_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::BN254_DOUBLE as u32)
            .or_insert(0);
        self.bn254_double_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::BLS12381_ADD as u32)
            .or_insert(0);
        self.bls12381_add_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::BLS12381_DOUBLE as u32)
            .or_insert(0);
        self.bls12381_double_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });
        self.bls12381_double_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        let count = syscall_lookups
            .entry(SyscallCode::SHA_EXTEND as u32)
            .or_insert(0);
        self.sha_extend_events.iter().for_each(|event| {
            self.nonce_lookup.insert(
                event.lookup_id,
                ((*count % DEFERRED_SPLIT_THRESHOLD) * 48) as u32,
            );
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::SHA_COMPRESS as u32)
            .or_insert(0);
        self.sha_compress_events.iter().for_each(|event| {
            self.nonce_lookup.insert(
                event.lookup_id,
                ((*count % DEFERRED_SPLIT_THRESHOLD) * 80) as u32,
            );
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::ED_ADD as u32)
            .or_insert(0);
        self.ed_add_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::ED_DECOMPRESS as u32)
            .or_insert(0);
        self.ed_decompress_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::SECP256K1_DECOMPRESS as u32)
            .or_insert(0);
        self.k256_decompress_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::UINT256_MUL as u32)
            .or_insert(0);
        self.uint256_mul_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });

        let count = syscall_lookups
            .entry(SyscallCode::BLS12381_DECOMPRESS as u32)
            .or_insert(0);
        self.bls12381_decompress_events.iter().for_each(|event| {
            self.nonce_lookup
                .insert(event.lookup_id, (*count % DEFERRED_SPLIT_THRESHOLD) as u32);
            *count += 1;
        });
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    /// the public values digest is used by the prover.
    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }
}

impl ExecutionRecord {
    pub fn new(program: Arc<Program>) -> Self {
        Self {
            program,
            ..Default::default()
        }
    }

    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    pub fn add_alu_events(&mut self, mut alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for (opcode, value) in alu_events.iter_mut() {
            match opcode {
                Opcode::ADD => {
                    self.add_events.append(value);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.append(value);
                }
                Opcode::SUB => {
                    self.sub_events.append(value);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.append(value);
                }
                Opcode::SLL => {
                    self.shift_left_events.append(value);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events.append(value);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.append(value);
                }
                _ => {
                    panic!("Invalid opcode: {:?}", opcode);
                }
            }
        }
    }

    /// Take out events from the [ExecutionRecord] that should be deferred to a separate shard.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every shard.
    pub fn defer(&mut self) -> ExecutionRecord {
        ExecutionRecord {
            keccak_permute_events: std::mem::take(&mut self.keccak_permute_events),
            secp256k1_add_events: std::mem::take(&mut self.secp256k1_add_events),
            secp256k1_double_events: std::mem::take(&mut self.secp256k1_double_events),
            bn254_add_events: std::mem::take(&mut self.bn254_add_events),
            bn254_double_events: std::mem::take(&mut self.bn254_double_events),
            bls12381_add_events: std::mem::take(&mut self.bls12381_add_events),
            bls12381_double_events: std::mem::take(&mut self.bls12381_double_events),
            sha_extend_events: std::mem::take(&mut self.sha_extend_events),
            sha_compress_events: std::mem::take(&mut self.sha_compress_events),
            ed_add_events: std::mem::take(&mut self.ed_add_events),
            ed_decompress_events: std::mem::take(&mut self.ed_decompress_events),
            k256_decompress_events: std::mem::take(&mut self.k256_decompress_events),
            uint256_mul_events: std::mem::take(&mut self.uint256_mul_events),
            bls12381_decompress_events: std::mem::take(&mut self.bls12381_decompress_events),
            memory_initialize_events: std::mem::take(&mut self.memory_initialize_events),
            memory_finalize_events: std::mem::take(&mut self.memory_finalize_events),
            ..Default::default()
        }
    }

    /// Splits the deferred [ExecutionRecord] into multiple [ExecutionRecord]s, each which contain
    /// a "reasonable" number of deferred events.
    pub fn split(&mut self, last: bool) -> Vec<ExecutionRecord> {
        let mut shards = Vec::new();

        macro_rules! split_events {
            ($self:ident, $events:ident, $shards:ident, $threshold:expr, $exact:expr) => {
                let events = std::mem::take(&mut $self.$events);
                let chunks = events.chunks_exact($threshold);
                if !$exact {
                    $self.$events = chunks.remainder().to_vec();
                } else {
                    let remainder = chunks.remainder().to_vec();
                    if !remainder.is_empty() {
                        $shards.push(ExecutionRecord {
                            $events: chunks.remainder().to_vec(),
                            program: self.program.clone(),
                            ..Default::default()
                        });
                    }
                }
                let mut event_shards = chunks
                    .map(|chunk| ExecutionRecord {
                        $events: chunk.to_vec(),
                        program: self.program.clone(),
                        ..Default::default()
                    })
                    .collect::<Vec<_>>();
                $shards.append(&mut event_shards);
            };
        }

        split_events!(
            self,
            keccak_permute_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            secp256k1_add_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            secp256k1_double_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            bn254_add_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            bn254_double_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            bls12381_add_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            bls12381_double_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            sha_extend_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            sha_compress_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(self, ed_add_events, shards, DEFERRED_SPLIT_THRESHOLD, last);
        split_events!(
            self,
            ed_decompress_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            k256_decompress_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            uint256_mul_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );
        split_events!(
            self,
            bls12381_decompress_events,
            shards,
            DEFERRED_SPLIT_THRESHOLD,
            last
        );

        if last {
            self.memory_initialize_events
                .sort_by_key(|event| event.addr);
            self.memory_finalize_events.sort_by_key(|event| event.addr);
            let mut init_addr_bits = [0; 32];
            let mut finalize_addr_bits = [0; 32];
            for (mem_init_chunk, mem_finalize_chunk) in self
                .memory_initialize_events
                .chunks(DEFERRED_SPLIT_THRESHOLD)
                .zip(self.memory_finalize_events.chunks(DEFERRED_SPLIT_THRESHOLD))
            {
                let mut shard = ExecutionRecord::default();
                shard.program = self.program.clone();
                shard
                    .memory_initialize_events
                    .extend_from_slice(mem_init_chunk);
                shard.public_values.previous_init_addr_bits = init_addr_bits;
                if let Some(last_event) = mem_init_chunk.last() {
                    let last_init_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    shard.public_values.last_init_addr_bits = last_init_addr_bits;
                    init_addr_bits = last_init_addr_bits;
                }

                shard
                    .memory_finalize_events
                    .extend_from_slice(mem_finalize_chunk);
                shard.public_values.previous_finalize_addr_bits = finalize_addr_bits;
                if let Some(last_event) = mem_finalize_chunk.last() {
                    let last_finalize_addr_bits =
                        core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    shard.public_values.last_finalize_addr_bits = last_finalize_addr_bits;
                    finalize_addr_bits = last_finalize_addr_bits;
                }

                shards.push(shard);
            }
        }

        shards
    }
}

impl ByteRecord for ExecutionRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self
            .byte_lookups
            .entry(blu_event.shard)
            .or_default()
            .entry(blu_event)
            .or_insert(0) += 1
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    pub a: Option<MemoryRecordEnum>,
    pub b: Option<MemoryRecordEnum>,
    pub c: Option<MemoryRecordEnum>,
    pub memory: Option<MemoryRecordEnum>,
}

/// The threshold for splitting deferred events.
pub const DEFERRED_SPLIT_THRESHOLD: usize = 1 << 19;
