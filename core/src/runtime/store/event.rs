use serde::Serialize;

use crate::{alu::Alu, cpu::Cpu};

/// An event to be recorded in the execution trace.
pub trait Event: Serialize {
    fn core(cpu: Cpu) -> Self;
    fn alu(cpu: Cpu, alu: Alu) -> Self;
}

/// A minimal implementation of an event.
#[derive(Clone, Debug, Serialize)]
pub enum BaseEvent {
    Core(Cpu),
    Alu(Cpu, Alu),
}

impl Event for BaseEvent {
    fn core(cpu: Cpu) -> Self {
        Self::Core(cpu)
    }

    fn alu(cpu: Cpu, alu: Alu) -> Self {
        Self::Alu(cpu, alu)
    }
}
