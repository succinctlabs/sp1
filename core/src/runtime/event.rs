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
    Mul(AluEvent),
    Add(AluEvent),
    Sub(AluEvent),
    Bitwise(AluEvent),
    ShiftLeft(AluEvent),
    ShiftRight(AluEvent),
    Divrem(AluEvent),
    Lt(AluEvent),
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

trait EventReceiver {
    fn receive(&mut self, event: RuntimeEvent);
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

impl EventReceiver for SimpleEventReceiver {
    fn receive(&mut self, event: RuntimeEvent) {
        match event {
            RuntimeEvent::Cpu(cpu_event) => {
                self.record.add_cpu_event(cpu_event);
            }
            RuntimeEvent::Mul(alu_event)
            | RuntimeEvent::Add(alu_event)
            | RuntimeEvent::Sub(alu_event)
            | RuntimeEvent::Bitwise(alu_event)
            | RuntimeEvent::ShiftLeft(alu_event)
            | RuntimeEvent::ShiftRight(alu_event)
            | RuntimeEvent::Divrem(alu_event)
            | RuntimeEvent::Lt(alu_event) => {
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
    tx: mpsc::Sender<Option<RuntimeEvent>>,
    rx: mpsc::Receiver<ExecutionRecord>,
    _phantom: std::marker::PhantomData<SC>,
}
impl<SC: StarkGenericConfig + Send + 'static> BufferedEventProcessor<SC> {
    pub fn new(buffer_size: usize, machine: RiscvStark<SC>) -> Self {
        let (tx, rx) = mpsc::channel();

        let (result_tx, result_rx) = mpsc::channel();

        thread::spawn(move || {
            let mut num_received = 0_u32;
            let mut record = ExecutionRecord::default();
            let mut receiver = SimpleEventReceiver::new();
            while let Some(event) = rx.recv().unwrap() {
                num_received += 1;
                // Process the event.
                receiver.receive(event);
                // Periodically, generate dependencies.
                if num_received % buffer_size as u32 == 0 {
                    let current_record = std::mem::take(&mut receiver.record);
                    let chips = machine.chips();
                    chips.iter().for_each(|chip| {
                        chip.generate_dependencies(&current_record, &mut record);
                    });
                }
            }
            let current_record = std::mem::take(&mut receiver.record);
            let chips = machine.chips();
            chips.iter().for_each(|chip| {
                chip.generate_dependencies(&current_record, &mut record);
            });
            result_tx.send(record).unwrap();
        });

        Self {
            tx,
            rx: result_rx,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn close(&mut self) -> ExecutionRecord {
        self.tx.send(None).unwrap();
        self.rx.recv().unwrap()
    }
}

impl<SC: StarkGenericConfig> EventReceiver for BufferedEventProcessor<SC> {
    fn receive(&mut self, event: RuntimeEvent) {
        self.tx.send(Some(event)).unwrap();
    }
}
