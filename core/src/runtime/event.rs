use std::sync::mpsc;
use std::thread;

use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::field::event::FieldEvent;
use crate::syscall::precompiles::blake3::Blake3CompressInnerEvent;
use crate::syscall::precompiles::edwards::EdDecompressEvent;
use crate::syscall::precompiles::k256::K256DecompressEvent;
use crate::syscall::precompiles::keccak256::KeccakPermuteEvent;
use crate::syscall::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};

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
}

trait EventReceiver {
    fn receive(&mut self, event: RuntimeEvent);
}

pub struct SimpleEventReceiver {
    record: ExecutionRecord,
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
        }
    }
}

pub struct BufferedEventProcessor {
    tx: mpsc::Sender<Option<RuntimeEvent>>,
    thread: thread::JoinHandle<()>,
}

impl BufferedEventProcessor {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            rx.iter().for_each(|event| {
                if let Some(event) = event {
                    // Process the event.
                }
            });
        });

        Self { tx, thread: handle }
    }

    pub fn close(&mut self) -> ExecutionRecord {
        self.tx.send(None).unwrap();
        self.thread.join().unwrap();
        ExecutionRecord::default()
    }
}

impl EventReceiver for BufferedEventProcessor {
    fn receive(&mut self, event: RuntimeEvent) {
        self.tx.send(Some(event)).unwrap();
    }
}
