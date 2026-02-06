//! An implementation of an exucutor for the SP1 RISC-V zkVM.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::struct_excessive_bools)]
#![warn(missing_docs)]

mod air;
mod context;
mod debug;
mod disassembler;
mod errors;
pub mod events;
mod hook;
mod instruction;
mod tracing;
pub use tracing::TracingVM;
mod vm;
pub use vm::{
    gas::get_complexity_mapping,
    memory::CompressedMemory,
    results::CycleResult,
    shapes::{MAXIMUM_CYCLE_AREA, MAXIMUM_PADDING_AREA},
    CoreVM,
};
mod splicing;
pub use splicing::{SplicedMinimalTrace, SplicingVM};
mod estimating;
pub use estimating::GasEstimatingVM;

mod minimal;
pub use minimal::*;

mod memory;
mod opcode;
mod opts;
#[cfg(feature = "profiling")]
mod profiler;
mod program;
mod record;
mod register;
mod report;
mod retain;
mod state;
pub mod subproof;
mod syscall_code;
pub use syscall_code::*;
mod utils;

pub use air::*;
pub use context::*;
pub use errors::*;
pub use hook::*;
pub use instruction::*;
// pub use minimal::*;
pub use opcode::*;
pub use opts::*;
pub use program::*;
pub use record::*;
pub use register::*;
pub use report::*;
pub use retain::*;
pub use state::*;
pub use utils::*;

pub use sp1_hypercube::SP1RecursionProof;

/// The default increment for the program counter. Is used for all instructions except
/// for branches and jumps.
pub const PC_INC: u32 = 4;

/// The default increment for the timestamp.
pub const CLK_INC: u32 = 8;

/// The executor uses this PC to determine if the program has halted.
/// As a PC, it is invalid since it is not a multiple of [`PC_INC`].
pub const HALT_PC: u64 = 1;

/// The number of rows in the `ByteChip`.
pub const BYTE_NUM_ROWS: u64 = 1 << 16;

/// The number of rows in the `RangeChip`.
pub const RANGE_NUM_ROWS: u64 = 1 << 17;

/// A module for testing programs.
#[cfg(test)]
pub mod programs {
    #[allow(dead_code)]
    #[allow(missing_docs)]
    pub mod tests {
        use crate::{utils::add_halt, Instruction, Opcode, Program};

        pub use test_artifacts::{
            FIBONACCI_ELF, PANIC_ELF, SECP256R1_ADD_ELF, SECP256R1_DOUBLE_ELF, SSZ_WITHDRAWALS_ELF,
            U256XU2048_MUL_ELF,
        };

        #[must_use]
        pub fn simple_program() -> Program {
            let mut instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
                Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            ];
            add_halt(&mut instructions);
            Program::new(instructions, 0, 0)
        }

        /// Get the fibonacci program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn fibonacci_program() -> Program {
            Program::from(&FIBONACCI_ELF).unwrap()
        }

        /// Get the secp256r1 add program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn secp256r1_add_program() -> Program {
            Program::from(&SECP256R1_ADD_ELF).unwrap()
        }

        /// Get the secp256r1 double program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn secp256r1_double_program() -> Program {
            Program::from(&SECP256R1_DOUBLE_ELF).unwrap()
        }

        /// Get the u256x2048 mul program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn u256xu2048_mul_program() -> Program {
            Program::from(&U256XU2048_MUL_ELF).unwrap()
        }

        /// Get the SSZ withdrawals program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn ssz_withdrawals_program() -> Program {
            Program::from(&SSZ_WITHDRAWALS_ELF).unwrap()
        }

        /// Get the panic program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn panic_program() -> Program {
            Program::from(&PANIC_ELF).unwrap()
        }

        #[must_use]
        #[allow(clippy::unreadable_literal)]
        pub fn simple_memory_program() -> Program {
            let mut instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
                // SW and LW
                Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LW, 28, 0, 0x27654320, false, true),
                // LBU
                Instruction::new(Opcode::LBU, 27, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LBU, 26, 0, 0x27654321, false, true),
                Instruction::new(Opcode::LBU, 25, 0, 0x27654322, false, true),
                Instruction::new(Opcode::LBU, 24, 0, 0x27654323, false, true),
                // LB
                Instruction::new(Opcode::LB, 23, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LB, 22, 0, 0x27654321, false, true),
                // LHU
                Instruction::new(Opcode::LHU, 21, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LHU, 20, 0, 0x27654322, false, true),
                // LH
                Instruction::new(Opcode::LH, 19, 0, 0x27654320, false, true),
                Instruction::new(Opcode::LH, 18, 0, 0x27654322, false, true),
                // SB
                Instruction::new(Opcode::ADD, 17, 0, 0x38276525, false, true),
                // Save the value 0x12348765 into address 0x43627530
                Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627530, false, true),
                Instruction::new(Opcode::LW, 16, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627531, false, true),
                Instruction::new(Opcode::LW, 15, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627532, false, true),
                Instruction::new(Opcode::LW, 14, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SB, 17, 0, 0x43627533, false, true),
                Instruction::new(Opcode::LW, 13, 0, 0x43627530, false, true),
                // SH
                // Save the value 0x12348765 into address 0x43627530
                Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SH, 17, 0, 0x43627530, false, true),
                Instruction::new(Opcode::LW, 12, 0, 0x43627530, false, true),
                Instruction::new(Opcode::SH, 17, 0, 0x43627532, false, true),
                Instruction::new(Opcode::LW, 11, 0, 0x43627530, false, true),
                // 64-bit operations for RISCV64 testing
                // Create a 64-bit value to test with
                Instruction::new(Opcode::ADD, 10, 0, 0xFEDCBA9876543210, false, true),
                // SD (Store Double/64-bit) and LD (Load Double/64-bit)
                Instruction::new(Opcode::SD, 10, 0, 0x54321000, false, true),
                Instruction::new(Opcode::LD, 9, 0, 0x54321000, false, true),
                // LWU (Load Word Unsigned) - loads 32-bit value and zero-extends to 64-bit
                Instruction::new(Opcode::LWU, 8, 0, 0x27654320, false, true),
                // Test that LWU zero-extends (upper 32 bits should be 0)
                Instruction::new(Opcode::LWU, 7, 0, 0x54321000, false, true), /* Load lower 32
                                                                               * bits of our
                                                                               * 64-bit value */
            ];
            add_halt(&mut instructions);
            Program::new(instructions, 0, 0)
        }
    }
}
