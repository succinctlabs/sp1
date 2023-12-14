use std::collections::BTreeMap;

use crate::runtime::runtime::Register;

mod air;
pub mod trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemOp {
    Read = 0,
    Write = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryEvent {
    pub addr: u32,
    pub clk: u32,
    pub op: MemOp,
    pub value: u32,
}

pub struct Memory {
    max_memory: u32,
    memory: BTreeMap<u32, u32>,
    registers: [u32; 32],
    memory_events: Vec<MemoryEvent>,
}

impl Memory {
    pub fn new(max_memory: u32) -> Self {
        assert_eq!(max_memory % 4, 0, "Memory size must be a multiple of 4");
        assert!(
            max_memory < u32::MAX - 31,
            "Memory size must be smaller than 2^32 - 32"
        );
        Self {
            max_memory,
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

    pub fn read_register(&mut self, clk: u32, reg: Register) -> u32 {
        let value = self.registers[reg as usize];
        let addr = self.max_memory + reg as u32;
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
        let addr = self.max_memory + reg as u32;
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op: MemOp::Write,
            value,
        });
    }
}
