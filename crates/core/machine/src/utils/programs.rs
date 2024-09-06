#![cfg(test)]

use sp1_core_executor::Program;

/// Tests.
use test_artifacts::{FIBONACCI_ELF, KECCAK_PERMUTE_ELF, PANIC_ELF};

/// Get the fibonacci program.
///
/// # Panics
///
/// This function will panic if the program fails to load.
#[must_use]
pub fn fibonacci_program() -> Program {
    Program::from(FIBONACCI_ELF).unwrap()
}

/// Get the SSZ withdrawals program.
///
/// # Panics
///
/// This function will panic if the program fails to load.
#[must_use]
pub fn ssz_withdrawals_program() -> Program {
    Program::from(KECCAK_PERMUTE_ELF).unwrap()
}

/// Get the panic program.
///
/// # Panics
///
/// This function will panic if the program fails to load.
#[must_use]
pub fn panic_program() -> Program {
    Program::from(PANIC_ELF).unwrap()
}
