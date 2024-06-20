use std::collections::BTreeMap;
use std::collections::HashMap;
use std::mem::take;
use std::sync::Arc;

use itertools::Itertools;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

use super::program::Program;
use super::Opcode;
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

/// A record of the execution of a program. Contains event data for everything that happened during
/// the execution of the shard.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// The index of the shard.
    pub index: u32,

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

    /// All byte lookups that are needed. The layout is shard -> (event -> count). Byte lookups are
    /// sharded to prevent the multiplicities from overflowing.
    pub byte_lookups: BTreeMap<u32, BTreeMap<ByteLookupEvent, usize>>,

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

    fn index(&self) -> u32 {
        self.index
    }

    fn set_index(&mut self, index: u32) {
        self.index = index;
    }

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

    fn shard(mut self, config: &ShardingConfig) -> Vec<Self> {
        // Get the number of CPU events.
        let num_cpu_events = self.cpu_events.len();

        // Create empty shards that we will fill in.
        let mut shards: Vec<ExecutionRecord> = Vec::new();

        // Iterate throught he CPU events and fill in the shards.
        let mut start_idx = 0;
        let mut current_shard = self.cpu_events[0].shard;
        for (i, cpu_event) in self.cpu_events.iter().enumerate() {
            let at_last_event = i == num_cpu_events - 1;
            if cpu_event.shard != current_shard || at_last_event {
                let last_idx = if at_last_event { i + 1 } else { i };

                // Fill in the shard.
                let mut shard = ExecutionRecord::default();
                shard.index = current_shard;
                shard.cpu_events = self.cpu_events[start_idx..last_idx].to_vec();
                shard.program = self.program.clone();

                // Byte lookups are already sharded, so put this shard's lookups in.
                let current_byte_lookups =
                    self.byte_lookups.remove(&current_shard).unwrap_or_default();
                shard
                    .byte_lookups
                    .insert(current_shard, current_byte_lookups);
                let last_shard_cpu_event = shard.cpu_events.last().unwrap();

                // Set the public_values_digest for all shards.  For the vast majority of the time, only the last shard
                // will read the public values.  But in some very rare edge cases, the last two shards will
                // read it (e.g. when the halt instruction is the only instruction in the last shard).
                // It seems overly complex to set the public_values_digest for the last two shards, so we just set it
                // for all of the shards.
                shard.public_values.committed_value_digest =
                    self.public_values.committed_value_digest;
                shard.public_values.deferred_proofs_digest =
                    self.public_values.deferred_proofs_digest;
                shard.public_values.shard = current_shard;
                shard.public_values.start_pc = shard.cpu_events[0].pc;
                shard.public_values.next_pc = last_shard_cpu_event.next_pc;
                shard.public_values.exit_code = last_shard_cpu_event.exit_code;
                shards.push(shard);

                if !(at_last_event) {
                    start_idx = i;
                    current_shard += 1;
                }
            }
        }

        // Shard the ADD events.
        for (add_chunk, shard) in take(&mut self.add_events)
            .chunks_mut(config.add_len)
            .zip(shards.iter_mut())
        {
            shard.add_events.extend_from_slice(add_chunk);
            for (i, event) in add_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Shard the SUB events.
        for (sub_chunk, shard) in take(&mut self.sub_events)
            .chunks_mut(config.sub_len)
            .zip(shards.iter_mut())
        {
            shard.sub_events.extend_from_slice(sub_chunk);
            for (i, event) in sub_chunk.iter().enumerate() {
                self.nonce_lookup
                    .insert(event.lookup_id, shard.add_events.len() as u32 + i as u32);
            }
        }

        // Shard the MUL events.
        for (mul_chunk, shard) in take(&mut self.mul_events)
            .chunks_mut(config.mul_len)
            .zip(shards.iter_mut())
        {
            shard.mul_events.extend_from_slice(mul_chunk);
            for (i, event) in mul_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Shard the bitwise events.
        for (bitwise_chunk, shard) in take(&mut self.bitwise_events)
            .chunks_mut(config.bitwise_len)
            .zip(shards.iter_mut())
        {
            shard.bitwise_events.extend_from_slice(bitwise_chunk);
            for (i, event) in bitwise_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Shard the shift left events.
        for (shift_left_chunk, shard) in take(&mut self.shift_left_events)
            .chunks_mut(config.shift_left_len)
            .zip(shards.iter_mut())
        {
            shard.shift_left_events.extend_from_slice(shift_left_chunk);
            for (i, event) in shift_left_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Shard the shift right events.
        for (shift_right_chunk, shard) in take(&mut self.shift_right_events)
            .chunks_mut(config.shift_right_len)
            .zip(shards.iter_mut())
        {
            shard
                .shift_right_events
                .extend_from_slice(shift_right_chunk);
            for (i, event) in shift_right_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Shard the divrem events.
        for (divrem_chunk, shard) in take(&mut self.divrem_events)
            .chunks_mut(config.divrem_len)
            .zip(shards.iter_mut())
        {
            shard.divrem_events.extend_from_slice(divrem_chunk);
            for (i, event) in divrem_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Shard the LT events.
        for (lt_chunk, shard) in take(&mut self.lt_events)
            .chunks_mut(config.lt_len)
            .zip(shards.iter_mut())
        {
            shard.lt_events.extend_from_slice(lt_chunk);
            for (i, event) in lt_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Keccak-256 permute events.
        for (keccak_chunk, shard) in take(&mut self.keccak_permute_events)
            .chunks_mut(config.keccak_len)
            .zip(shards.iter_mut())
        {
            shard.keccak_permute_events.extend_from_slice(keccak_chunk);
            for (i, event) in keccak_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, (i * 24) as u32);
            }
        }

        // secp256k1 curve add events.
        for (secp256k1_add_chunk, shard) in take(&mut self.secp256k1_add_events)
            .chunks_mut(config.secp256k1_add_len)
            .zip(shards.iter_mut())
        {
            shard
                .secp256k1_add_events
                .extend_from_slice(secp256k1_add_chunk);
            for (i, event) in secp256k1_add_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // secp256k1 curve double events.
        for (secp256k1_double_chunk, shard) in take(&mut self.secp256k1_double_events)
            .chunks_mut(config.secp256k1_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .secp256k1_double_events
                .extend_from_slice(secp256k1_double_chunk);
            for (i, event) in secp256k1_double_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // bn254 curve add events.
        for (bn254_add_chunk, shard) in take(&mut self.bn254_add_events)
            .chunks_mut(config.bn254_add_len)
            .zip(shards.iter_mut())
        {
            shard.bn254_add_events.extend_from_slice(bn254_add_chunk);
            for (i, event) in bn254_add_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // bn254 curve double events.
        for (bn254_double_chunk, shard) in take(&mut self.bn254_double_events)
            .chunks_mut(config.bn254_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .bn254_double_events
                .extend_from_slice(bn254_double_chunk);
            for (i, event) in bn254_double_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // BLS12-381 curve add events.
        for (bls12381_add_chunk, shard) in take(&mut self.bls12381_add_events)
            .chunks_mut(config.bls12381_add_len)
            .zip(shards.iter_mut())
        {
            shard
                .bls12381_add_events
                .extend_from_slice(bls12381_add_chunk);
            for (i, event) in bls12381_add_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // BLS12-381 curve double events.
        for (bls12381_double_chunk, shard) in take(&mut self.bls12381_double_events)
            .chunks_mut(config.bls12381_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .bls12381_double_events
                .extend_from_slice(bls12381_double_chunk);
            for (i, event) in bls12381_double_chunk.iter().enumerate() {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            }
        }

        // Put the precompile events in the first shard.
        let first = shards.first_mut().unwrap();

        // SHA-256 extend events.
        first.sha_extend_events = std::mem::take(&mut self.sha_extend_events);
        for (i, event) in first.sha_extend_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, (i * 48) as u32);
        }

        // SHA-256 compress events.
        first.sha_compress_events = std::mem::take(&mut self.sha_compress_events);
        for (i, event) in first.sha_compress_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, (i * 80) as u32);
        }

        // Edwards curve add events.
        first.ed_add_events = std::mem::take(&mut self.ed_add_events);
        for (i, event) in first.ed_add_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        }

        // Edwards curve decompress events.
        first.ed_decompress_events = std::mem::take(&mut self.ed_decompress_events);
        for (i, event) in first.ed_decompress_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        }

        // K256 curve decompress events.
        first.k256_decompress_events = std::mem::take(&mut self.k256_decompress_events);
        for (i, event) in first.k256_decompress_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        }

        // Uint256 mul arithmetic events.
        first.uint256_mul_events = std::mem::take(&mut self.uint256_mul_events);
        for (i, event) in first.uint256_mul_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        }

        // Bls12-381 decompress events .
        first.bls12381_decompress_events = std::mem::take(&mut self.bls12381_decompress_events);
        for (i, event) in first.bls12381_decompress_events.iter().enumerate() {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        }

        // Put MemoryInit / MemoryFinalize events in the last shard.
        let last = shards.last_mut().unwrap();
        last.memory_initialize_events
            .extend_from_slice(&self.memory_initialize_events);
        last.memory_finalize_events
            .extend_from_slice(&self.memory_finalize_events);

        // Copy the nonce lookup to all shards.
        for shard in shards.iter_mut() {
            shard.nonce_lookup.clone_from(&self.nonce_lookup);
        }

        shards
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    /// the public values digest is used by the prover.
    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }
}

impl ExecutionRecord {
    pub fn new(index: u32, program: Arc<Program>) -> Self {
        Self {
            index,
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

    pub fn add_alu_events(&mut self, alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        let keys = alu_events.keys().sorted();
        for opcode in keys {
            match opcode {
                Opcode::ADD => {
                    self.add_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SUB => {
                    self.sub_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SLL => {
                    self.shift_left_events
                        .extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events
                        .extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.extend_from_slice(&alu_events[opcode]);
                }
                _ => {
                    panic!("Invalid opcode: {:?}", opcode);
                }
            }
        }
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
