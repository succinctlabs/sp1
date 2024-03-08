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

use super::ExecutionRecord;

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

pub struct SimpleEventReceiver {
    pub record: ExecutionRecord,
}

impl SimpleEventReceiver {
    pub fn new() -> Self {
        Self {
            record: ExecutionRecord::default(),
        }
    }
}

impl EventHandler for SimpleEventReceiver {
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
            let mut receiver = SimpleEventReceiver::new();
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
                            chip.generate_dependencies(&current_record, &mut record);
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
