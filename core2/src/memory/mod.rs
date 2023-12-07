use valida_machine::Operands;

pub struct MemoryEvent {
    pub clk: u32,
    pub addr: u32,
    pub value: Word<u8>,
}

struct MemoryTrace {}

impl MemoryTrace {
    fn generate_trace(events: Vec<CpuEvent>) {
        todo!();
    }
}
