use std::collections::HashMap;

use crate::runtime::{Opcode, SyscallCode};

/// Holds data describing the result of a program's execution.
#[derive(Debug, Clone, Default)]
pub struct ExecutionResult {
    /// Total number of cycles used by the execution.
    pub global_clk: u64,

    /// Total number of instructions executed, broken down by opcode.
    pub opcode_count: HashMap<Opcode, u32>,

    /// Total number of syscalls executed, broken down by syscall code.
    pub syscall_count: HashMap<SyscallCode, u32>,
}

impl ExecutionResult {
    pub fn new() -> Self {
        ExecutionResult {
            global_clk: 0,
            opcode_count: HashMap::new(),
            syscall_count: HashMap::new(),
        }
    }

    pub fn add_to_opcode_count(&mut self, opcode: Opcode) {
        *self.opcode_count.entry(opcode).or_insert(0) += 1;
    }

    pub fn add_to_syscall_count(&mut self, code: SyscallCode) {
        *self.syscall_count.entry(code).or_insert(0) += 1;
    }
}
