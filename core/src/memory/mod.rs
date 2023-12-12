use std::collections::BTreeMap;

use crate::runtime::Register;

mod air;
pub mod trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemOp {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryEvent {
    pub clk: u32,
    pub addr: u32,
    pub op: MemOp,
    pub value: u32,
}

pub struct Memory {
    MAX_MEMORY: u32,
    memory: BTreeMap<u32, u32>,
    registers: [u32; 32],
    memory_events: Vec<MemoryEvent>,
}

impl Memory {
    pub fn new(MAX_MEMORY: u32) -> Self {
        Self {
            MAX_MEMORY,
            memory: BTreeMap::new(),
            registers: [0; 32],
            memory_events: Vec::new(),
        }
    }

    pub fn read(&mut self, clk: u32, addr: u32) -> u32 {
        let value = self.memory.get(&addr).expect("Unititialized memory");
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Read,
            value: *value,
        });
        *value
    }

    pub fn write(&mut self, clk: u32, addr: u32, value: u32) {
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Write,
            value,
        });
        self.memory.insert(addr, value);
    }

    pub fn read_register(&mut self, clk: u32, reg: Register, value: u32) -> u32 {
        let value = self.registers[reg as usize];
        let addr = self.MAX_MEMORY + reg as u32;
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Read,
            value,
        });
        value
    }

    pub fn write_register(&mut self, clk: u32, reg: Register, value: u32) {
        self.registers[reg as usize] = value;
        let addr = self.MAX_MEMORY + reg as u32;
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Write,
            value,
        });
    }
}
