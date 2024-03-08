use std::sync::mpsc;
use std::thread;

use crate::air::MachineAir;
use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::{CpuEvent, MemoryRecord};
use crate::field::event::FieldEvent;
use crate::syscall::precompiles::blake3::Blake3CompressInnerEvent;
use crate::syscall::precompiles::edwards::EdDecompressEvent;
use crate::syscall::precompiles::k256::K256DecompressEvent;
use crate::syscall::precompiles::keccak256::KeccakPermuteEvent;
use crate::syscall::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};
use crate::RiscvStark;
use crate::StarkGenericConfig;

use super::{ExecutionRecord, Opcode, ShardingConfig};

#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    Cpu(CpuEvent),
    Alu(AluEvent),
    ByteLookup(ByteLookupEvent),
    Field(FieldEvent),
    ShaExtend(Box<ShaExtendEvent>),
    ShaCompress(Box<ShaCompressEvent>),
    KeccakPermute(Box<KeccakPermuteEvent>),
    EdAdd(Box<ECAddEvent>),
    EdDecompress(Box<EdDecompressEvent>),
    WeierstrassAdd(Box<ECAddEvent>),
    WeierstrassDouble(Box<ECDoubleEvent>),
    K256Decompress(Box<K256DecompressEvent>),
    Blake3CompressInner(Box<Blake3CompressInnerEvent>),
    FirstMemory(Vec<(u32, MemoryRecord, u32)>),
    LastMemory(Vec<(u32, MemoryRecord, u32)>),
    ProgramMemory(Vec<(u32, MemoryRecord, u32)>),
}

pub trait EventHandler {
    fn handle(&mut self, event: RuntimeEvent);
}

pub struct DummyEventReceiver;

impl EventHandler for DummyEventReceiver {
    fn handle(&mut self, _event: RuntimeEvent) {}
}

pub struct SimpleEventRecorder {
    pub record: ExecutionRecord,
}

impl SimpleEventRecorder {
    pub fn new() -> Self {
        Self {
            record: ExecutionRecord::default(),
        }
    }
}

impl EventHandler for SimpleEventRecorder {
    fn handle(&mut self, event: RuntimeEvent) {
        match event {
            RuntimeEvent::Cpu(cpu_event) => {
                self.record.add_cpu_event(cpu_event);
            }
            RuntimeEvent::Alu(alu_event) => {
                self.record.add_alu_event(alu_event);
            }
            RuntimeEvent::ByteLookup(byte_lookup_event) => {
                self.record.add_byte_lookup_event(byte_lookup_event);
            }
            RuntimeEvent::Field(field_event) => {
                self.record.add_field_event(field_event);
            }
            RuntimeEvent::ShaExtend(sha_extend_event) => {
                self.record.sha_extend_events.push(*sha_extend_event);
            }
            RuntimeEvent::ShaCompress(sha_compress_event) => {
                self.record.sha_compress_events.push(*sha_compress_event);
            }
            RuntimeEvent::KeccakPermute(keccak_permute_event) => {
                self.record
                    .keccak_permute_events
                    .push(*keccak_permute_event);
            }
            RuntimeEvent::EdAdd(ed_add_event) => {
                self.record.ed_add_events.push(*ed_add_event);
            }
            RuntimeEvent::EdDecompress(ed_decompress_event) => {
                self.record.ed_decompress_events.push(*ed_decompress_event);
            }
            RuntimeEvent::WeierstrassAdd(weierstrass_add_event) => {
                self.record
                    .weierstrass_add_events
                    .push(*weierstrass_add_event);
            }
            RuntimeEvent::WeierstrassDouble(weierstrass_double_event) => {
                self.record
                    .weierstrass_double_events
                    .push(*weierstrass_double_event);
            }
            RuntimeEvent::K256Decompress(k256_decompress_event) => {
                self.record
                    .k256_decompress_events
                    .push(*k256_decompress_event);
            }
            RuntimeEvent::Blake3CompressInner(blake3_compress_inner_event) => {
                self.record
                    .blake3_compress_inner_events
                    .push(*blake3_compress_inner_event);
            }
            RuntimeEvent::FirstMemory(record) => {
                self.record.first_memory_record = record;
            }
            RuntimeEvent::LastMemory(record) => {
                self.record.last_memory_record = record;
            }
            RuntimeEvent::ProgramMemory(record) => {
                self.record.program_memory_record = record;
            }
        }
    }
}

pub struct ShardingEventRecorder {
    shards: Vec<ExecutionRecord>,
    config: ShardingConfig,
    add_shard: usize,
    mul_shard: usize,
    sub_shard: usize,
    bitwise_shard: usize,
    shift_left_shard: usize,
    shift_right_shard: usize,
    divrem_shard: usize,
    lt_shard: usize,
    field_shard: usize,
    sha_extend_shard: usize,
    sha_compress_shard: usize,
    keccak_permute_shard: usize,
    ed_add_shard: usize,
    ed_decompress_shard: usize,
    weierstrass_add_shard: usize,
    weierstrass_double_shard: usize,
    k256_decompress_shard: usize,
    blake3_compress_inner_shard: usize,
    first_memory_record: Vec<(u32, MemoryRecord, u32)>,
    last_memory_record: Vec<(u32, MemoryRecord, u32)>,
    program_memory_record: Vec<(u32, MemoryRecord, u32)>,
}

impl ShardingEventRecorder {
    pub fn new(config: ShardingConfig) -> Self {
        Self {
            shards: vec![ExecutionRecord::default()],
            config,
            add_shard: 0,
            mul_shard: 0,
            sub_shard: 0,
            bitwise_shard: 0,
            shift_left_shard: 0,
            shift_right_shard: 0,
            divrem_shard: 0,
            lt_shard: 0,
            field_shard: 0,
            sha_extend_shard: 0,
            sha_compress_shard: 0,
            keccak_permute_shard: 0,
            ed_add_shard: 0,
            ed_decompress_shard: 0,
            weierstrass_add_shard: 0,
            weierstrass_double_shard: 0,
            k256_decompress_shard: 0,
            blake3_compress_inner_shard: 0,
            first_memory_record: vec![],
            last_memory_record: vec![],
            program_memory_record: vec![],
        }
    }

    fn ingest_events<T: Clone>(
        &mut self,
        dst: &mut Vec<T>,
        next_shard: Option<&mut Vec<T>>,
        src: &Vec<T>,
        max: usize,
    ) {
        let space_left = max - dst.len();
        dst.extend_from_slice(&src[..space_left]);
        let mut remaining = &src[space_left..];
        if remaining.len() > 0 {
            let shard = next_shard.unwrap();
            shard.extend_from_slice(&remaining);
        }
    }

    pub fn ingest_record(&mut self, record: ExecutionRecord) {
        let cpu_shard = &mut self.shards.last_mut().unwrap();
        let space_left = self.config.shard_size - cpu_shard.cpu_events.len();
        cpu_shard
            .cpu_events
            .extend_from_slice(&record.cpu_events[..space_left]);
        let mut remaining_cpu_events = &record.cpu_events[space_left..];
        if remaining_cpu_events.len() > 0 {
            self.shards.push(ExecutionRecord::default());
            let cpu_shard = &mut self.shards.last_mut().unwrap();
            cpu_shard
                .cpu_events
                .extend_from_slice(&remaining_cpu_events);
        }
        self.ingest_events(
            &mut self.shards[self.add_shard].add_events,
            self.shards
                .get_mut(self.add_shard + 1)
                .map(|x| &mut x.add_events),
            &record.add_events,
            self.config.add_len,
        );
        self.ingest_events(
            &mut self.shards[self.mul_shard].mul_events,
            self.shards
                .get_mut(self.mul_shard + 1)
                .map(|x| &mut x.mul_events),
            &record.mul_events,
            self.config.mul_len,
        );
        self.ingest_events(
            &mut self.shards[self.sub_shard].sub_events,
            self.shards
                .get_mut(self.sub_shard + 1)
                .map(|x| &mut x.sub_events),
            &record.sub_events,
            self.config.sub_len,
        );
        self.ingest_events(
            &mut self.shards[self.bitwise_shard].bitwise_events,
            self.shards
                .get_mut(self.bitwise_shard + 1)
                .map(|x| &mut x.bitwise_events),
            &record.bitwise_events,
            self.config.bitwise_len,
        );
        self.ingest_events(
            &mut self.shards[self.shift_left_shard].shift_left_events,
            self.shards
                .get_mut(self.shift_left_shard + 1)
                .map(|x| &mut x.shift_left_events),
            &record.shift_left_events,
            self.config.shift_left_len,
        );
        self.ingest_events(
            &mut self.shards[self.shift_right_shard].shift_right_events,
            self.shards
                .get_mut(self.shift_right_shard + 1)
                .map(|x| &mut x.shift_right_events),
            &record.shift_right_events,
            self.config.shift_right_len,
        );
        self.ingest_events(
            &mut self.shards[self.divrem_shard].divrem_events,
            self.shards
                .get_mut(self.divrem_shard + 1)
                .map(|x| &mut x.divrem_events),
            &record.divrem_events,
            self.config.divrem_len,
        );
        self.ingest_events(
            &mut self.shards[self.lt_shard].lt_events,
            self.shards
                .get_mut(self.lt_shard + 1)
                .map(|x| &mut x.lt_events),
            &record.lt_events,
            self.config.lt_len,
        );
        for (byte_lookup, count) in record.byte_lookups {
            let mut shard = &mut self.shards[0];
            shard
                .byte_lookups
                .entry(byte_lookup)
                .and_modify(|i| *i += count)
                .or_insert(count);
        }
        self.ingest_events(
            &mut self.shards[self.field_shard].field_events,
            self.shards
                .get_mut(self.field_shard + 1)
                .map(|x| &mut x.field_events),
            &record.field_events,
            self.config.field_len,
        );
        self.ingest_events(
            &mut self.shards[self.sha_extend_shard].sha_extend_events,
            self.shards
                .get_mut(self.sha_extend_shard + 1)
                .map(|x| &mut x.sha_extend_events),
            &record.sha_extend_events,
            self.config.shard_size,
        );
        self.ingest_events(
            &mut self.shards[self.sha_compress_shard].sha_compress_events,
            self.shards
                .get_mut(self.sha_compress_shard + 1)
                .map(|x| &mut x.sha_compress_events),
            &record.sha_compress_events,
            self.config.shard_size,
        );
        self.ingest_events(
            &mut self.shards[self.keccak_permute_shard].keccak_permute_events,
            self.shards
                .get_mut(self.keccak_permute_shard + 1)
                .map(|x| &mut x.keccak_permute_events),
            &record.keccak_permute_events,
            self.config.keccak_len,
        );
        self.ingest_events(
            &mut self.shards[self.ed_add_shard].ed_add_events,
            self.shards
                .get_mut(self.ed_add_shard + 1)
                .map(|x| &mut x.ed_add_events),
            &record.ed_add_events,
            self.config.shard_size,
        );
        self.ingest_events(
            &mut self.shards[self.ed_decompress_shard].ed_decompress_events,
            self.shards
                .get_mut(self.ed_decompress_shard + 1)
                .map(|x| &mut x.ed_decompress_events),
            &record.ed_decompress_events,
            self.config.shard_size,
        );
        self.ingest_events(
            &mut self.shards[self.weierstrass_add_shard].weierstrass_add_events,
            self.shards
                .get_mut(self.weierstrass_add_shard + 1)
                .map(|x| &mut x.weierstrass_add_events),
            &record.weierstrass_add_events,
            self.config.weierstrass_add_len,
        );
        self.ingest_events(
            &mut self.shards[self.weierstrass_double_shard].weierstrass_double_events,
            self.shards
                .get_mut(self.weierstrass_double_shard + 1)
                .map(|x| &mut x.weierstrass_double_events),
            &record.weierstrass_double_events,
            self.config.weierstrass_double_len,
        );
        self.ingest_events(
            &mut self.shards[self.k256_decompress_shard].k256_decompress_events,
            self.shards
                .get_mut(self.k256_decompress_shard + 1)
                .map(|x| &mut x.k256_decompress_events),
            &record.k256_decompress_events,
            self.config.shard_size,
        );
        self.ingest_events(
            &mut self.shards[self.blake3_compress_inner_shard].blake3_compress_inner_events,
            self.shards
                .get_mut(self.blake3_compress_inner_shard + 1)
                .map(|x| &mut x.blake3_compress_inner_events),
            &record.blake3_compress_inner_events,
            self.config.shard_size,
        );
        self.first_memory_record = record.first_memory_record;
        self.last_memory_record = record.last_memory_record;
        self.program_memory_record = record.program_memory_record;
    }
}

impl EventHandler for ShardingEventRecorder {
    fn handle(&mut self, event: RuntimeEvent) {
        match event {
            RuntimeEvent::Cpu(cpu_event) => {
                let mut shard = self.shards.last_mut().unwrap();
                if shard.cpu_events.len() == self.config.shard_size {
                    self.shards.push(ExecutionRecord::default());
                    shard = self.shards.last_mut().unwrap();
                }
                shard.add_cpu_event(cpu_event);
            }
            RuntimeEvent::Alu(alu_event) => {
                let mut shard;
                match alu_event.opcode {
                    Opcode::ADD => {
                        shard = &mut self.shards[self.add_shard];
                        if shard.add_events.len() == self.config.shard_size {
                            self.add_shard += 1;
                            shard = &mut self.shards[self.add_shard];
                        }
                    }
                    Opcode::SUB => {
                        shard = &mut self.shards[self.sub_shard];
                        if shard.sub_events.len() == self.config.shard_size {
                            self.sub_shard += 1;
                            shard = &mut self.shards[self.sub_shard];
                        }
                    }
                    Opcode::XOR | Opcode::OR | Opcode::AND => {
                        shard = &mut self.shards[self.bitwise_shard];
                        if shard.bitwise_events.len() == self.config.shard_size {
                            self.bitwise_shard += 1;
                            shard = &mut self.shards[self.bitwise_shard];
                        }
                    }
                    Opcode::SLL => {
                        shard = &mut self.shards[self.shift_left_shard];
                        if shard.shift_left_events.len() == self.config.shard_size {
                            self.shift_left_shard += 1;
                            shard = &mut self.shards[self.shift_left_shard];
                        }
                    }
                    Opcode::SRL | Opcode::SRA => {
                        shard = &mut self.shards[self.shift_right_shard];
                        if shard.shift_right_events.len() == self.config.shard_size {
                            self.shift_right_shard += 1;
                            shard = &mut self.shards[self.shift_right_shard];
                        }
                    }
                    Opcode::SLT | Opcode::SLTU => {
                        shard = &mut self.shards[self.lt_shard];
                        if shard.lt_events.len() == self.config.shard_size {
                            self.lt_shard += 1;
                            shard = &mut self.shards[self.lt_shard];
                        }
                    }
                    Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH => {
                        shard = &mut self.shards[self.mul_shard];
                        if shard.mul_events.len() == self.config.shard_size {
                            self.mul_shard += 1;
                            shard = &mut self.shards[self.mul_shard];
                        }
                    }
                    Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
                        shard = &mut self.shards[self.divrem_shard];
                        if shard.divrem_events.len() == self.config.shard_size {
                            self.divrem_shard += 1;
                            shard = &mut self.shards[self.divrem_shard];
                        }
                    }
                    _ => {
                        panic!("Invalid ALU opcode: {:?}", alu_event.opcode);
                    }
                }
                shard.add_alu_event(alu_event);
            }
            RuntimeEvent::ByteLookup(event) => {
                self.shards[0].add_byte_lookup_event(event);
            }
            RuntimeEvent::Field(event) => {
                let mut shard = &mut self.shards[self.field_shard];
                if shard.field_events.len() == self.config.field_len {
                    self.field_shard += 1;
                    shard = &mut self.shards[self.field_shard];
                }
                shard.add_field_event(event);
            }
            RuntimeEvent::ShaExtend(event) => {
                let mut shard = &mut self.shards[self.sha_extend_shard];
                if shard.sha_extend_events.len() == self.config.shard_size {
                    self.sha_extend_shard += 1;
                    shard = &mut self.shards[self.sha_extend_shard];
                }
                shard.sha_extend_events.push(*event);
            }
            RuntimeEvent::ShaCompress(event) => {
                let mut shard = &mut self.shards[self.sha_compress_shard];
                if shard.sha_compress_events.len() == self.config.shard_size {
                    self.sha_compress_shard += 1;
                    shard = &mut self.shards[self.sha_compress_shard];
                }
                shard.sha_compress_events.push(*event);
            }
            RuntimeEvent::KeccakPermute(event) => {
                let mut shard = &mut self.shards[self.keccak_permute_shard];
                if shard.keccak_permute_events.len() == self.config.keccak_len {
                    self.keccak_permute_shard += 1;
                    shard = &mut self.shards[self.keccak_permute_shard];
                }
                shard.keccak_permute_events.push(*event);
            }
            RuntimeEvent::EdAdd(event) => {
                let mut shard = &mut self.shards[self.ed_add_shard];
                if shard.ed_add_events.len() == self.config.shard_size {
                    self.ed_add_shard += 1;
                    shard = &mut self.shards[self.ed_add_shard];
                }
                shard.ed_add_events.push(*event);
            }
            RuntimeEvent::EdDecompress(event) => {
                let mut shard = &mut self.shards[self.ed_decompress_shard];
                if shard.ed_decompress_events.len() == self.config.shard_size {
                    self.ed_decompress_shard += 1;
                    shard = &mut self.shards[self.ed_decompress_shard];
                }
                shard.ed_decompress_events.push(*event);
            }
            RuntimeEvent::WeierstrassAdd(event) => {
                let mut shard = &mut self.shards[self.weierstrass_add_shard];
                if shard.weierstrass_add_events.len() == self.config.shard_size {
                    self.weierstrass_add_shard += 1;
                    shard = &mut self.shards[self.weierstrass_add_shard];
                }
                shard.weierstrass_add_events.push(*event);
            }
            RuntimeEvent::WeierstrassDouble(event) => {
                let mut shard = &mut self.shards[self.weierstrass_double_shard];
                if shard.weierstrass_double_events.len() == self.config.shard_size {
                    self.weierstrass_double_shard += 1;
                    shard = &mut self.shards[self.weierstrass_double_shard];
                }
                shard.weierstrass_double_events.push(*event);
            }
            RuntimeEvent::K256Decompress(event) => {
                let mut shard = &mut self.shards[self.k256_decompress_shard];
                if shard.k256_decompress_events.len() == self.config.shard_size {
                    self.k256_decompress_shard += 1;
                    shard = &mut self.shards[self.k256_decompress_shard];
                }
                shard.k256_decompress_events.push(*event);
            }
            RuntimeEvent::Blake3CompressInner(event) => {
                let mut shard = &mut self.shards[self.blake3_compress_inner_shard];
                if shard.blake3_compress_inner_events.len() == self.config.shard_size {
                    self.blake3_compress_inner_shard += 1;
                    shard = &mut self.shards[self.blake3_compress_inner_shard];
                }
                shard.blake3_compress_inner_events.push(*event);
            }
            RuntimeEvent::FirstMemory(record) => {
                self.first_memory_record = record;
            }
            RuntimeEvent::LastMemory(record) => {
                self.last_memory_record = record;
            }
            RuntimeEvent::ProgramMemory(record) => {
                self.program_memory_record = record;
            }
        }
    }
}

/// An event processor that sends events to another thread and periodically processes them, filling
/// out the record with all necessary events.
pub struct BufferedEventProcessor<SC: StarkGenericConfig> {
    // s: Option<kanal::Sender<RuntimeEvent>>,
    // r: kanal::Receiver<ExecutionRecord>,
    s: Option<mpsc::Sender<RuntimeEvent>>,
    r: mpsc::Receiver<ExecutionRecord>,
    _phantom: std::marker::PhantomData<SC>,
}
impl<SC: StarkGenericConfig + Send + 'static> BufferedEventProcessor<SC> {
    pub fn new(buffer_size: usize, machine: RiscvStark<SC>) -> Self {
        // let (s, r) = kanal::unbounded();
        let (s, r) = mpsc::channel();

        // let (result_s, result_r) = kanal::unbounded();
        let (result_s, result_r) = mpsc::channel();

        thread::spawn(move || {
            let mut num_received = 0_u32;
            let mut record = ExecutionRecord::default();
            let mut receiver = SimpleEventRecorder::new();
            let mut final_receiver = ShardingEventRecorder::new(ShardingConfig::default());
            for event in r {
                num_received += 1;
                // Process the event.
                receiver.handle(event);
                // Periodically, generate dependencies.
                if num_received % buffer_size as u32 == 0 {
                    log::info!("BufferedEventProcessor: received {} events", num_received);
                    let mut current_record = std::mem::take(&mut receiver.record);
                    let chips = machine.chips();
                    tracing::trace_span!("generate_dependencies").in_scope(|| {
                        chips.iter().for_each(|chip| {
                            chip.generate_dependencies(&current_record, &mut final_receiver);
                        });
                    });
                    record.append(&mut current_record);
                }
            }
            let mut current_record = std::mem::take(&mut receiver.record);
            let chips = machine.chips();
            chips.iter().for_each(|chip| {
                chip.generate_dependencies(&current_record, &mut record);
            });
            record.append(&mut current_record);
            result_s.send(record).unwrap();
        });

        Self {
            s: Some(s),
            r: result_r,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn close(&mut self) -> ExecutionRecord {
        self.s = None;
        self.r.recv().unwrap()
    }
}

impl<SC: StarkGenericConfig> EventHandler for BufferedEventProcessor<SC> {
    fn handle(&mut self, event: RuntimeEvent) {
        self.s
            .as_ref()
            .expect("already closed")
            .send(event)
            .unwrap();
    }
}
