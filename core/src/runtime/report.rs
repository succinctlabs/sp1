use crate::runtime::{Instruction, Opcode, Register, Runtime, SyscallCode};
use std::collections::HashMap;
use std::default::Default;
use strum::IntoEnumIterator;

/// A summary report of execution statistics that are not directly used for proving.
#[derive(Default, Debug)]
pub struct ExecutionReport {
    /// The total number of clock cycles executed.
    pub cycles: u64,

    // These internal maps are kept private so that we can expose the report's invariant that all
    // possible opcodes and syscalls have valid entries.
    opcode_counts: HashMap<Opcode, u64>,
    syscall_counts: HashMap<SyscallCode, u64>,
}

impl ExecutionReport {
    pub fn new() -> Self {
        Self {
            cycles: 0,
            opcode_counts: Opcode::iter().map(|opc| (opc, 0)).collect(),
            syscall_counts: SyscallCode::iter().map(|sc| (sc, 0)).collect(),
        }
    }

    /// The number of times `op` instructions have been executed.
    pub fn opcode_count(&self, op: Opcode) -> u64 {
        *self.opcode_counts.get(&op).unwrap()
    }

    /// The number of times `syscall` calls have been made.
    pub fn syscall_count(&self, syscall: SyscallCode) -> u64 {
        *self.syscall_counts.get(&syscall).unwrap()
    }

    /// Update the report statistics when a new instruction is dispatched.
    pub fn update(&mut self, runtime: &Runtime, instruction: &Instruction) {
        self.cycles += 1;

        self.opcode_counts
            .entry(instruction.opcode)
            .and_modify(|c| *c += 1);

        if instruction.opcode == Opcode::ECALL {
            let syscall = SyscallCode::from_u32(runtime.register(Register::X5));
            self.syscall_counts.entry(syscall).and_modify(|c| *c += 1);
        }
    }
}
