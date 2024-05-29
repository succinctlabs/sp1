use super::Runtime;
use std::{any::Any, collections::HashMap};

use thiserror::Error;

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

/// A report containing useful information about the execution of a program.
/// It stores useful information about the resource footprint of a provable
/// RISCV program, including number of cycles, instruction count, and syscall
/// count.
///
/// ### Custom Metrics:
/// An execution report contains a rich set of metrics and granular details
/// that can be easily accessed. You can, for example, count the total
/// number of ADD instructions that occurred during a program run:
/// ```
/// use sp1_core::runtime::{Instruction, Opcode, Program, Register, Runtime, SP1CoreOpts};
///
/// // Simple program to test the ADD instruction
/// let instructions = vec![
///     Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
///     Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
///     Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
/// ];
///
/// // Setup a program and a runtime
/// let program = Program::new(instructions, 0, 0);
/// let mut runtime = Runtime::new(program, SP1CoreOpts::default());
/// // Runtime must execute to produce runtime statistics
/// let mut res = runtime.run().unwrap();
///
/// // Retrieve the number of ADD operations
/// let add_count = &res.get_metric("Arithmetic", "ADD").unwrap_or(0);
/// assert_eq!(*add_count, 3);
///
/// // You can also get a count of all opcode occurences by category
/// let memory_operations_count = res.get_total_for_category("Arithmetic").unwrap_or(0);
/// assert_eq!(memory_operations_count, 3,);
/// ```
#[derive(Debug)]
pub struct ExecutionReport {
    /// Total number of cycles occurred during program execution
    pub cycles: u32,
    /// Total number of instructions occurred during program execution
    pub total_instruction_count: usize,
    /// Total number of syscalls occurred during program execution
    pub syscall_count: usize,
    /// Contains precise counts of each individual instruction,
    /// as well as counts of instruction by category. See [ExecutionReport] Usage for
    /// more details
    pub custom_metrics: HashMap<String, Box<dyn Any>>,
}

impl ExecutionReport {
    /// Accept a runtime from a program which has already executed
    /// and extract some useful information from it.
    pub fn new(runtime: &Runtime) -> Self {
        let total_instruction_count = runtime
            .instruction_log
            .values()
            .map(|counts| counts.values().sum::<u64>() as usize)
            .sum();

        let syscall_count = runtime
            .instruction_log
            .get("Syscalls")
            .map_or(0, |counts| counts.values().sum::<u64>() as usize);

        let mut custom_metrics = HashMap::new();
        for (category, counts) in &runtime.instruction_log {
            // Convert the inner HashMap to a format that can be boxed as `dyn Any`
            let metrics: HashMap<_, _> = counts
                .iter()
                .map(|(opcode, count)| (format!("{:?}", opcode), *count))
                .collect();
            custom_metrics.insert(category.clone(), Box::new(metrics) as Box<dyn Any>);
        }

        Self {
            cycles: runtime.state.clk,
            total_instruction_count,
            syscall_count,
            custom_metrics,
        }
    }

    /// Retrieve specific metric based on category and opcode.
    pub fn get_metric(&self, category: &str, opcode: &str) -> Result<u64, MetricRetrievalError> {
        let boxed_map = self
            .custom_metrics
            .get(category)
            .ok_or(MetricRetrievalError::CategoryNotFound)?;

        let map = boxed_map
            .downcast_ref::<HashMap<String, u64>>()
            .ok_or(MetricRetrievalError::DataTypeMismatch)?;

        let count = map
            .get(opcode)
            .copied()
            .ok_or(MetricRetrievalError::OpcodeNotFound)?;

        Ok(count)
    }

    /// Retrieve the total count of all operations for a given category.
    pub fn get_total_for_category(&self, category: &str) -> Result<u64, MetricRetrievalError> {
        let boxed_map = self
            .custom_metrics
            .get(category)
            .ok_or(MetricRetrievalError::CategoryNotFound)?;

        let map = boxed_map
            .downcast_ref::<HashMap<String, u64>>()
            .ok_or(MetricRetrievalError::DataTypeMismatch)?;

        Ok(map.values().sum())
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
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];

        // Setup a program and a runtime
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        // Runtime must execute to report runtime statistics
        let res = runtime.dry_run().unwrap();
        assert_eq!(runtime.register(Register::X31), 42);

        // Retrieve the number of ADD operations
        let add_count = &res.get_metric("Arithmetic", "ADD").unwrap_or(0);
        assert_eq!(*add_count, 3);
        assert_eq!(res.cycles, 12);
        assert_eq!(res.total_instruction_count, 3);

        // You can also get a count of all opcode occurences by category
        let memory_operations_count = res.get_total_for_category("Arithmetic").unwrap_or(0);
        assert_eq!(memory_operations_count, 3,);
    }
}
