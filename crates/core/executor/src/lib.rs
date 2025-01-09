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
mod cost;
mod dependencies;
mod disassembler;
pub mod events;
mod executor;
mod hook;
mod instruction;
mod io;
mod memory;
mod opcode;
#[cfg(feature = "profiling")]
mod profiler;
mod program;
mod record;
mod reduce;
mod register;
mod report;
mod state;
pub mod subproof;
pub mod syscalls;
mod utils;

pub use air::*;
pub use context::*;
pub use cost::*;
pub use executor::*;
pub use hook::*;
pub use instruction::*;
pub use opcode::*;
pub use program::*;
pub use record::*;
pub use reduce::*;
pub use register::*;
pub use report::*;
pub use state::*;
pub use utils::*;

#[cfg(test)]
pub mod programs {
    #[allow(dead_code)]
    #[allow(missing_docs)]
    pub mod tests {
        use crate::{Instruction, Opcode, Program};

        pub use test_artifacts::{
            FIBONACCI_ELF, PANIC_ELF, SECP256R1_ADD_ELF, SECP256R1_DOUBLE_ELF, SSZ_WITHDRAWALS_ELF,
            U256XU2048_MUL_ELF,
        };

        #[must_use]
        pub fn simple_program() -> Program {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
                Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            ];
            Program::new(instructions, 0, 0)
        }

        /// Get the fibonacci program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn fibonacci_program() -> Program {
            Program::from(FIBONACCI_ELF).unwrap()
        }

        /// Get the secp256r1 add program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn secp256r1_add_program() -> Program {
            Program::from(SECP256R1_ADD_ELF).unwrap()
        }

        /// Get the secp256r1 double program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn secp256r1_double_program() -> Program {
            Program::from(SECP256R1_DOUBLE_ELF).unwrap()
        }

        /// Get the u256x2048 mul program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn u256xu2048_mul_program() -> Program {
            Program::from(U256XU2048_MUL_ELF).unwrap()
        }

        /// Get the SSZ withdrawals program.
        ///
        /// # Panics
        ///
        /// This function will panic if the program fails to load.
        #[must_use]
        pub fn ssz_withdrawals_program() -> Program {
            Program::from(SSZ_WITHDRAWALS_ELF).unwrap()
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

        #[must_use]
        #[allow(clippy::unreadable_literal)]
        pub fn simple_memory_program() -> Program {
            let instructions = vec![
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
                // LU
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
            ];
            Program::new(instructions, 0, 0)
        }
    }
}
