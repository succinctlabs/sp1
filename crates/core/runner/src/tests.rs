use crate::MinimalExecutorRunner;
use sp1_core_executor::{ExecutionError, Program, DEFAULT_MEMORY_LIMIT};
use sp1_core_machine::{io::SP1Stdin, utils::setup_logger};
use std::sync::Arc;
use test_artifacts::MEMORY_TESTER_ELF;

fn run(runner: &mut MinimalExecutorRunner) -> Option<ExecutionError> {
    loop {
        match runner.try_execute_chunk() {
            Ok(Some(_)) => (), // continue
            Ok(None) => return None,
            Err(e) => return Some(e),
        }
    }
}

#[test]
fn test_out_of_bound_access() {
    setup_logger();

    let program = Arc::new(Program::from(&MEMORY_TESTER_ELF).expect("parse program"));
    let mut stdin = SP1Stdin::new();
    stdin.write(&0u8);

    let mut runner =
        MinimalExecutorRunner::new(program, false, Some(1000), DEFAULT_MEMORY_LIMIT, 1);
    for input in &stdin.buffer {
        runner.with_input(input);
    }

    let result = run(&mut runner);
    assert!(matches!(result, Some(ExecutionError::InvalidMemoryAccess(_, _))));
}

#[test]
fn test_using_too_much_memory() {
    setup_logger();

    let program = Arc::new(Program::from(&MEMORY_TESTER_ELF).expect("parse program"));
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8);

    // 2 executors treat memory limit differently, here we are using different
    // limit numbers respectively.
    #[cfg(sp1_use_native_executor)]
    let memory_limit = 2 * 1024 * 1024 * 1024;
    #[cfg(not(sp1_use_native_executor))]
    let memory_limit = 8 * 256 * 1024;

    let mut runner = MinimalExecutorRunner::new(program, false, Some(16000000), memory_limit, 1);
    for input in &stdin.buffer {
        runner.with_input(input);
    }

    let result = run(&mut runner);
    assert_eq!(result, Some(ExecutionError::TooMuchMemory()));
}
