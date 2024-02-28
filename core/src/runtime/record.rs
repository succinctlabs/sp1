use hashbrown::HashMap;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::program::Program;
use super::Opcode;
use crate::alu::AluEvent;
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::cpu::{CpuEvent, MemoryRecordEnum};
use crate::field::event::FieldEvent;
use crate::runtime::MemoryRecord;
use crate::syscall::precompiles::blake3::Blake3CompressInnerEvent;
use crate::syscall::precompiles::edwards::EdDecompressEvent;
use crate::syscall::precompiles::k256::K256DecompressEvent;
use crate::syscall::precompiles::keccak256::KeccakPermuteEvent;
use crate::syscall::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};
use crate::utils::env;
use serde::{Deserialize, Serialize};

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

    /// A trace of the byte lookups needed.
    pub byte_lookups: BTreeMap<ByteLookupEvent, usize>,

    /// A trace of field LTU events.
    pub field_events: Vec<FieldEvent>,

    pub sha_extend_events: Vec<ShaExtendEvent>,

    pub sha_compress_events: Vec<ShaCompressEvent>,

    pub keccak_permute_events: Vec<KeccakPermuteEvent>,

    pub ed_add_events: Vec<ECAddEvent>,

    pub ed_decompress_events: Vec<EdDecompressEvent>,

    pub weierstrass_add_events: Vec<ECAddEvent>,

    pub weierstrass_double_events: Vec<ECDoubleEvent>,

    pub k256_decompress_events: Vec<K256DecompressEvent>,

    pub blake3_compress_inner_events: Vec<Blake3CompressInnerEvent>,

    /// Information needed for global chips. This shouldn't really be here but for legacy reasons,
    /// we keep this information in this struct for now.
    pub first_memory_record: Vec<(u32, MemoryRecord, u32)>,
    pub last_memory_record: Vec<(u32, MemoryRecord, u32)>,
    pub program_memory_record: Vec<(u32, MemoryRecord, u32)>,
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
    pub weierstrass_add_len: usize,
    pub weierstrass_double_len: usize,
}

impl ShardingConfig {
    pub const fn shard_size(&self) -> usize {
        self.shard_size
    }
}

impl Default for ShardingConfig {
    fn default() -> Self {
        let shard_size = env::shard_size();
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
            weierstrass_add_len: shard_size,
            weierstrass_double_len: shard_size,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ShardStats {
    pub nb_cpu_events: usize,
    pub nb_add_events: usize,
    pub nb_mul_events: usize,
    pub nb_sub_events: usize,
    pub nb_bitwise_events: usize,
    pub nb_shift_left_events: usize,
    pub nb_shift_right_events: usize,
    pub nb_divrem_events: usize,
    pub nb_lt_events: usize,
    pub nb_field_events: usize,
    pub nb_sha_extend_events: usize,
    pub nb_sha_compress_events: usize,
    pub nb_keccak_permute_events: usize,
    pub nb_ed_add_events: usize,
    pub nb_ed_decompress_events: usize,
    pub nb_weierstrass_add_events: usize,
    pub nb_weierstrass_double_events: usize,
    pub nb_k256_decompress_events: usize,
}

impl ExecutionRecord {
    pub fn new(index: u32, program: Arc<Program>) -> Self {
        Self {
            index,
            program,
            ..Default::default()
        }
    }

    pub fn shard(self, config: &ShardingConfig) -> Vec<Self> {
        // Make the shard vector by splitting CPU and program events.
        let mut shards = self
            .cpu_events
            .chunks(config.shard_size())
            .enumerate()
            .map(|(i, chunk)| {
                let mut shard = ExecutionRecord::default();
                shard.index = (i + 1) as u32;
                shard.cpu_events = chunk.to_vec();
                shard.program = self.program.clone();
                shard
            })
            .collect::<Vec<_>>();

        // Shard all the other events according to the configuration.

        // Shard the ADD events.
        for (add_chunk, shard) in self
            .add_events
            .chunks(config.add_len)
            .zip(shards.iter_mut())
        {
            shard.add_events.extend_from_slice(add_chunk);
        }

        // Shard the MUL events.
        for (mul_chunk, shard) in self
            .mul_events
            .chunks(config.mul_len)
            .zip(shards.iter_mut())
        {
            shard.mul_events.extend_from_slice(mul_chunk);
        }

        // Shard the SUB events.
        for (sub_chunk, shard) in self
            .sub_events
            .chunks(config.sub_len)
            .zip(shards.iter_mut())
        {
            shard.sub_events.extend_from_slice(sub_chunk);
        }

        // Shard the bitwise events.
        for (bitwise_chunk, shard) in self
            .bitwise_events
            .chunks(config.bitwise_len)
            .zip(shards.iter_mut())
        {
            shard.bitwise_events.extend_from_slice(bitwise_chunk);
        }

        // Shard the shift left events.
        for (shift_left_chunk, shard) in self
            .shift_left_events
            .chunks(config.shift_left_len)
            .zip(shards.iter_mut())
        {
            shard.shift_left_events.extend_from_slice(shift_left_chunk);
        }

        // Shard the shift right events.
        for (shift_right_chunk, shard) in self
            .shift_right_events
            .chunks(config.shift_right_len)
            .zip(shards.iter_mut())
        {
            shard
                .shift_right_events
                .extend_from_slice(shift_right_chunk);
        }

        // Shard the divrem events.
        for (divrem_chunk, shard) in self
            .divrem_events
            .chunks(config.divrem_len)
            .zip(shards.iter_mut())
        {
            shard.divrem_events.extend_from_slice(divrem_chunk);
        }

        // Shard the LT events.
        for (lt_chunk, shard) in self.lt_events.chunks(config.lt_len).zip(shards.iter_mut()) {
            shard.lt_events.extend_from_slice(lt_chunk);
        }

        // Shard the field events.
        for (field_chunk, shard) in self
            .field_events
            .chunks(config.field_len)
            .zip(shards.iter_mut())
        {
            shard.field_events.extend_from_slice(field_chunk);
        }

        // Keccak-256 permute events.
        for (keccak_chunk, shard) in self
            .keccak_permute_events
            .chunks(config.keccak_len)
            .zip(shards.iter_mut())
        {
            shard.keccak_permute_events.extend_from_slice(keccak_chunk);
        }

        // Weierstrass curve add events.
        for (weierstrass_add_chunk, shard) in self
            .weierstrass_add_events
            .chunks(config.weierstrass_add_len)
            .zip(shards.iter_mut())
        {
            shard
                .weierstrass_add_events
                .extend_from_slice(weierstrass_add_chunk);
        }

        // Weierstrass curve double events.
        for (weierstrass_double_chunk, shard) in self
            .weierstrass_double_events
            .chunks(config.weierstrass_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .weierstrass_double_events
                .extend_from_slice(weierstrass_double_chunk);
        }

        // Put the precompile events in the first shard.
        let first = shards.first_mut().unwrap();

        // SHA-256 extend events.
        first
            .sha_extend_events
            .extend_from_slice(&self.sha_extend_events);

        // SHA-256 compress events.
        first
            .sha_compress_events
            .extend_from_slice(&self.sha_compress_events);

        // Edwards curve add events.
        first.ed_add_events.extend_from_slice(&self.ed_add_events);

        // Edwards curve decompress events.
        first
            .ed_decompress_events
            .extend_from_slice(&self.ed_decompress_events);

        // K256 curve decompress events.
        first
            .k256_decompress_events
            .extend_from_slice(&self.k256_decompress_events);

        // Blake3 compress events .
        first
            .blake3_compress_inner_events
            .extend_from_slice(&self.blake3_compress_inner_events);

        // Put all byte lookups in the first shard (as the table size is fixed)
        first.byte_lookups.extend(&self.byte_lookups);

        // Put the memory records in the last shard.
        let last_shard = shards.last_mut().unwrap();

        last_shard
            .first_memory_record
            .extend_from_slice(&self.first_memory_record);
        last_shard
            .last_memory_record
            .extend_from_slice(&self.last_memory_record);
        last_shard
            .program_memory_record
            .extend_from_slice(&self.program_memory_record);

        shards
    }

    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    pub fn add_field_event(&mut self, field_event: FieldEvent) {
        self.field_events.push(field_event);
    }

    pub fn add_field_events(&mut self, field_events: &[FieldEvent]) {
        self.field_events.extend_from_slice(field_events);
    }

    pub fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.byte_lookups
            .entry(blu_event)
            .and_modify(|i| *i += 1)
            .or_insert(1);
    }

    pub fn add_alu_events(&mut self, alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for opcode in alu_events.keys() {
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

    pub fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events.iter() {
            self.add_byte_lookup_event(*blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b are indeed bytes to the shard.
    pub fn add_u8_range_check(&mut self, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a as u32,
            c: b as u32,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    pub fn add_u16_range_check(&mut self, a: u32) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    pub fn add_u8_range_checks(&mut self, ls: &[u8]) {
        let mut index = 0;
        while index + 1 < ls.len() {
            self.add_u8_range_check(ls[index], ls[index + 1]);
            index += 2;
        }
        if index < ls.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(ls[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    pub fn add_u16_range_checks(&mut self, ls: &[u32]) {
        ls.iter().for_each(|x| self.add_u16_range_check(*x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    pub fn lookup_or(&mut self, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::OR,
            a1: (b | c) as u32,
            a2: 0,
            b: b as u32,
            c: c as u32,
        });
    }

    pub fn stats(&self) -> ShardStats {
        ShardStats {
            nb_cpu_events: self.cpu_events.len(),
            nb_add_events: self.add_events.len(),
            nb_mul_events: self.mul_events.len(),
            nb_sub_events: self.sub_events.len(),
            nb_bitwise_events: self.bitwise_events.len(),
            nb_shift_left_events: self.shift_left_events.len(),
            nb_shift_right_events: self.shift_right_events.len(),
            nb_divrem_events: self.divrem_events.len(),
            nb_lt_events: self.lt_events.len(),
            nb_field_events: self.field_events.len(),
            nb_sha_extend_events: self.sha_extend_events.len(),
            nb_sha_compress_events: self.sha_compress_events.len(),
            nb_keccak_permute_events: self.keccak_permute_events.len(),
            nb_ed_add_events: self.ed_add_events.len(),
            nb_ed_decompress_events: self.ed_decompress_events.len(),
            nb_weierstrass_add_events: self.weierstrass_add_events.len(),
            nb_weierstrass_double_events: self.weierstrass_double_events.len(),
            nb_k256_decompress_events: self.k256_decompress_events.len(),
        }
    }

    /// Append the events from another execution record to this one, leaving the other one empty.
    pub fn append(&mut self, other: &mut ExecutionRecord) {
        assert_eq!(self.index, other.index, "Shard index mismatch");

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
        self.field_events.append(&mut other.field_events);
        self.sha_extend_events.append(&mut other.sha_extend_events);
        self.sha_compress_events
            .append(&mut other.sha_compress_events);
        self.keccak_permute_events
            .append(&mut other.keccak_permute_events);
        self.ed_add_events.append(&mut other.ed_add_events);
        self.ed_decompress_events
            .append(&mut other.ed_decompress_events);
        self.weierstrass_add_events
            .append(&mut other.weierstrass_add_events);
        self.weierstrass_double_events
            .append(&mut other.weierstrass_double_events);
        self.k256_decompress_events
            .append(&mut other.k256_decompress_events);
        self.blake3_compress_inner_events
            .append(&mut other.blake3_compress_inner_events);

        for (event, mult) in other.byte_lookups.iter_mut() {
            self.byte_lookups
                .entry(*event)
                .and_modify(|i| *i += *mult)
                .or_insert(*mult);
        }

        self.first_memory_record
            .append(&mut other.first_memory_record);
        self.last_memory_record
            .append(&mut other.last_memory_record);
        self.program_memory_record
            .append(&mut other.program_memory_record);
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct CpuRecord {
    pub a: Option<MemoryRecordEnum>,
    pub b: Option<MemoryRecordEnum>,
    pub c: Option<MemoryRecordEnum>,
    pub memory: Option<MemoryRecordEnum>,
}
