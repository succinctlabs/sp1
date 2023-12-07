use crate::alu::AluEvent;
use crate::cpu::CpuEvent;
use crate::memory::MemoryEvent;
use crate::ProgramROM;

pub struct Segment {
    pub cpu_events: Vec<CpuEvent>,
    pub memory_events: Vec<MemoryEvent>,
    pub alu_events: Vec<AluEvent>,
    // pub lookups: Vec<LookupEvent>,
    pub program: ProgramROM<i32>,
}

impl Segment {
    fn prove() {
        // Generate the traces based on each set of events.
        todo!()
    }

    fn verify() {
        todo!()
    }
}
