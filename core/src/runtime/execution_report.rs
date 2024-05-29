use super::{Opcode, Runtime, SyscallCode};
use std::collections::HashMap;
use thiserror::Error;

/// A report containing useful information about the execution of a program.
/// It stores useful information about the resource footprint of a provable
/// RISCV program, including the count of each operation and syscall that
/// occurred during execution.
///
/// ### Usage:
/// ```
/// use sp1_core::{
/// runtime::{Instruction, Opcode, Program, Register, Runtime},
/// utils::SP1CoreOpts,
/// };
/// let instructions = vec![
///     Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
///     Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
///     Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
/// ];
///
/// // Setup a program and a runtime
/// let program = Program::new(instructions, 0, 0);
/// let mut runtime = Runtime::new(program, SP1CoreOpts::default());
/// // Runtime must execute before reporting statistics
/// let report = runtime.dry_run().unwrap();
/// // Check that the count of ADD instructions is exactly 3
/// let add_count = report
/// .total_instruction_count
/// .get(&Opcode::ADD)
/// .unwrap_or(&0);
/// assert_eq!(*add_count, 3, "The count of ADD instructions should be 3");
/// // Verify successful ADD operations
/// assert_eq!(runtime.register(Register::X31), 42);
/// ```
#[derive(Debug)]
pub struct ExecutionReport {
    /// Total number of instructions occurred during program execution
    pub total_instruction_count: HashMap<Opcode, usize>,
    /// Total number of syscalls occurred during program execution
    pub total_syscall_count: HashMap<SyscallCode, usize>,
}

#[derive(Error, Debug)]
/// Errors which may occur when querying an execution report for
/// instruction details.
pub enum MetricRetrievalError {
    #[error("category not found")]
    CategoryNotFound,

    #[error("opcode not found in category")]
    OpcodeNotFound,

    #[error("data type mismatch for the stored metric")]
    DataTypeMismatch,
}

impl ExecutionReport {
    /// Accept a runtime from a program which has already executed
    /// and extract some useful information from it.
    pub fn new(runtime: &Runtime) -> Self {
        let mut total_instruction_count = HashMap::new();
        let mut total_syscall_count = HashMap::new();

        // Populate the total_instruction_count from the opcode log
        runtime.opcode_log.iter().for_each(|(&opcode, &count)| {
            *total_instruction_count.entry(opcode).or_insert(0) += count as usize;
        });

        // Populate the total_syscall_count from the syscall log
        runtime.syscall_log.iter().for_each(|(&syscall, &count)| {
            *total_syscall_count.entry(syscall).or_insert(0) += count as usize;
        });

        ExecutionReport {
            total_instruction_count,
            total_syscall_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        runtime::{Instruction, Opcode, Program, Register, Runtime},
        utils::SP1CoreOpts,
    };

    #[test]
    fn test_logging() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];

        // Setup a program and a runtime
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        // Runtime must execute before reporting statistics
        let report = runtime.dry_run().unwrap();
        // Check that the count of ADD instructions is exactly 3
        let add_count = report
            .total_instruction_count
            .get(&Opcode::ADD)
            .unwrap_or(&0);
        assert_eq!(*add_count, 3, "The count of ADD instructions should be 3");
        // Verify successful ADD operations
        assert_eq!(runtime.register(Register::X31), 42);
    }
}
