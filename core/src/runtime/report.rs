use crate::runtime::{Instruction, Opcode, Register, Runtime, SyscallCode};
use std::collections::HashMap;
use std::default::Default;

/// A summary report of execution statistics that are not directly used for proving.
#[derive(Default, Debug)]
pub struct ExecutionReport {
    /// The total number of clock cycles executed.
    pub cycles: u64,

    /// The number of times each opcode has been executed.
    pub opcode_counts: HashMap<Opcode, u64>,

    /// The number of times each syscall has been executed.
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

impl ExecutionReport {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn update(&mut self, instruction: &Instruction, runtime: &Runtime) {
        self.cycles += 1;

        self.opcode_counts
            .entry(instruction.opcode)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        if instruction.opcode == Opcode::ECALL {
            let syscall = SyscallCode::from_u32(runtime.register(Register::X5));
            self.syscall_counts
                .entry(syscall)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }
    }
}
