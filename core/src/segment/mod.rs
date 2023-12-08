use crate::alu::AluEvent;
use crate::cpu::CpuEvent;
use crate::program::ProgramROM;

pub struct Segment {
    pub cpu_events: Vec<CpuEvent>,
    pub alu_events: Vec<AluEvent>,
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
