use crate::syscall::precompiles::{MemoryReadRecord, MemoryWriteRecord};

mod air;
mod columns;
mod execute;
mod trace;

#[derive(Debug, Clone)]
pub struct FriFoldEvent {
    pub clk: u32,
    pub shard: u32,

    pub num: [u32; 4],
    pub denom: [u32; 4],

    pub input_slice_read_records: Vec<MemoryReadRecord>,
    pub input_slice_ptr: u32,
    pub output_slice_read_records: Vec<MemoryReadRecord>,
    pub output_slice_ptr: u32,

    pub ro_read_records: Vec<MemoryReadRecord>,
    pub ro_write_records: Vec<MemoryWriteRecord>,

    pub alpha_pow_read_records: Vec<MemoryReadRecord>,
    pub alpha_pow_write_records: Vec<MemoryWriteRecord>,
}

pub struct FriFoldChip {}

impl FriFoldChip {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod fri_fold_tests {
    use crate::air::DEGREE;
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
    use crate::runtime::Register;
    use crate::runtime::SyscallCode;
    use crate::utils::run_test;
    use crate::utils::setup_logger;
    use crate::utils::tests::BLAKE3_COMPRESS_ELF;
    use crate::Program;

    use super::columns::P_AT_X_IDX;
    use super::columns::P_AT_Z_START_IDX;
    use super::columns::Z_START_IDX;
    use super::columns::{ALPHA_START_IDX, X_IDX};

    pub fn fri_fold_internal_program() -> Program {
        let input_ptr = 100;
        let output_ptr = 500;
        let ro_addr = 1000;
        let alpha_pow_addr = 1500;
        let mut instructions = vec![];

        // Will test it with the following values.

        // input_ro: BinomialExtensionField { value: [1847687120, 1423454610, 1144640053, 1381242286] }
        // input_alpha_pow: BinomialExtensionField { value: [540044308, 1018290973, 627874647, 969069565] }
        // p_at_z: BinomialExtensionField { value: [1257978304, 1179973496, 1444690212, 456956341] }
        // p_at_x: 777132171
        // z: BinomialExtensionField { value: [1454407147, 568676784, 1977102820, 1323872866] }
        // x: is 31
        // alpha: BinomialExtensionField { value:  }

        // output_ro:  BinomialExtensionField { value: [1306862788, 594458733, 1798096294, 1881139490] }
        // output_alpha_pow: BinomialExtensionField { value: [1726063080, 1854443909, 1099989448, 144245555] }

        // Store 1000 + i in memory for the i-th word of the state. 1000 + i is an arbitrary
        // number that is easy to spot while debugging.

        let x = 31;
        let alpha_base_slice = [534846791, 266430563, 1876720999, 461694771];
        let z_base_slice = [1454407147, 568676784, 1977102820, 1323872866];
        let p_at_z_base_slice = [1257978304, 1179973496, 1444690212, 456956341];
        let p_at_x = 777132171;
        let input_ro_base_slice = [1847687120, 1423454610, 1144640053, 1381242286];
        let input_alpha_pow_base_slice = [540044308, 1018290973, 627874647, 969069565];

        for _i in 0..10 {
            // Save x into memory
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, x, false, true),
                Instruction::new(Opcode::ADD, 30, 0, input_ptr + X_IDX as u32, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);

            // Save alpha into memory
            for i in 0..DEGREE {
                instructions.extend(vec![
                    Instruction::new(Opcode::ADD, 29, 0, alpha_base_slice[i], false, true),
                    Instruction::new(
                        Opcode::ADD,
                        30,
                        0,
                        input_ptr + ((ALPHA_START_IDX + i) * 4) as u32,
                        false,
                        true,
                    ),
                    Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                ]);
            }

            // Save z into memory
            for i in 0..DEGREE {
                instructions.extend(vec![
                    Instruction::new(Opcode::ADD, 29, 0, z_base_slice[i], false, true),
                    Instruction::new(
                        Opcode::ADD,
                        30,
                        0,
                        input_ptr + ((Z_START_IDX + i) * 4) as u32,
                        false,
                        true,
                    ),
                    Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                ]);
            }

            // Save p_at_z into memory
            for i in 0..DEGREE {
                instructions.extend(vec![
                    Instruction::new(Opcode::ADD, 29, 0, p_at_z_base_slice[i], false, true),
                    Instruction::new(
                        Opcode::ADD,
                        30,
                        0,
                        input_ptr + ((P_AT_Z_START_IDX + i) * 4) as u32,
                        false,
                        true,
                    ),
                    Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                ]);
            }

            // Save p_at_x into memory
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, p_at_x, false, true),
                Instruction::new(
                    Opcode::ADD,
                    30,
                    0,
                    input_ptr + (P_AT_X_IDX * 4) as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);

            // Save input_ro_base_slice into ro memory
            for i in 0..DEGREE {
                instructions.extend(vec![
                    Instruction::new(Opcode::ADD, 29, 0, input_ro_base_slice[i], false, true),
                    Instruction::new(Opcode::ADD, 30, 0, ro_addr + (i * 4) as u32, false, true),
                    Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                ]);
            }

            // Save input_alpha_pow_base_slice into alpha_pow memory
            for i in 0..DEGREE {
                instructions.extend(vec![
                    Instruction::new(
                        Opcode::ADD,
                        29,
                        0,
                        input_alpha_pow_base_slice[i],
                        false,
                        true,
                    ),
                    Instruction::new(
                        Opcode::ADD,
                        30,
                        0,
                        alpha_pow_addr + (i * 4) as u32,
                        false,
                        true,
                    ),
                    Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                ]);
            }

            // Save ro_addr and alpha_pow_addr into output memory
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, ro_addr, false, true),
                Instruction::new(Opcode::ADD, 30, 0, output_ptr, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                Instruction::new(Opcode::ADD, 29, 0, alpha_pow_addr, false, true),
                Instruction::new(Opcode::ADD, 30, 0, output_ptr + 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);

            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 5, 0, SyscallCode::FRI_FOLD as u32, false, true),
                Instruction::new(Opcode::ADD, Register::X10 as u32, 0, input_ptr, false, true),
                Instruction::new(
                    Opcode::ADD,
                    Register::X11 as u32,
                    0,
                    output_ptr,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
            ]);
        }

        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = fri_fold_internal_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_blake3_compress_inner_elf() {
        setup_logger();
        let program = Program::from(BLAKE3_COMPRESS_ELF);
        run_test(program).unwrap();
    }
}
