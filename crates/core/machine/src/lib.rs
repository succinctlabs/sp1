#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap,
    clippy::default_constructed_unit_structs,
    clippy::box_default,
    clippy::assign_op_pattern,
    deprecated,
    incomplete_features
)]
#![warn(unused_extern_crates)]

pub mod air;
pub mod alu;
pub mod bytes;
pub mod control_flow;
pub mod cpu;
pub mod global;
pub mod io;
pub mod memory;
pub mod operations;
pub mod program;
pub mod riscv;
pub mod shape;
#[cfg(feature = "sys")]
pub mod sys;
pub mod syscall;
pub mod utils;

// Re-export the `SP1ReduceProof` struct from sp1_core_machine.
//
// This is done to avoid a circular dependency between sp1_core_machine and sp1_core_executor, and
// enable crates that depend on sp1_core_machine to import the `SP1ReduceProof` type directly.
pub mod reduce {
    pub use sp1_core_executor::SP1ReduceProof;
}

#[cfg(test)]
pub mod programs {
    #[allow(dead_code)]
    #[allow(missing_docs)]
    pub mod tests {
        use sp1_core_executor::{Instruction, Opcode, Program};

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
