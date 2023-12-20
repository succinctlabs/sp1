use rrs_lib::process_instruction;

use crate::disassembler::Opcode;

use super::{Instruction, InstructionTranspiler, Register};

/// Transpile the instructions from the 32-bit encoded instructions.
///
/// This step removes immediate instructions and replaces them with the corresponding register
/// instructions but with the immediate flags turned on. It also translates some unsupported
/// RISCV instructions (i.e., LUI) into supported instructions.
pub fn transpile(instructions_u32: &[u32]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut transpiler = InstructionTranspiler;
    for instruction_u32 in instructions_u32 {
        let instruction = process_instruction(&mut transpiler, *instruction_u32).unwrap();
        instructions.push(instruction);
    }
    instructions
}

/// Performs static analysis on the instructions to determine what opcodes/precompiles are being
/// used when `ecall`s are executed.
///
/// For example, the following code will be translated to a precompile instruction with "10" as the
/// argument:
///
///     addi %t0, x0, 10
///     ecall
///
/// Note that standard system calls set %a7, not %t0.
pub fn ecall_analysis_pass(instructions: &[Instruction]) -> Vec<Instruction> {
    let mut instructions_new = Vec::new();
    for i in 0..instructions.len() {
        // Ensure that the current instruction is an `ecall` instruction.
        let instruction = instructions[i];
        if instruction.opcode != Opcode::ECALL {
            instructions_new.push(instruction);
            continue;
        }

        // Ensure that the previous instruction is an `add` instruction that is setting %t0 with
        // an immediate value identifying what type of ecall it is.
        let prev_instruction = instructions[i - 1];
        if prev_instruction.opcode != Opcode::ADD
            || prev_instruction.op_a != Register::X5 as u32
            || prev_instruction.imm_c
        {
            instructions_new.push(instruction);
            continue;
        }

        // Translate the ecall to HALT, LWA, or PRECOMPILE depending on the value of %t0.
        let precompile_opcode = prev_instruction.op_c;
        let instruction = if precompile_opcode == Opcode::HALT as u32 {
            Instruction::new(Opcode::HALT, 0, 0, 0, false, false)
        } else if precompile_opcode == Opcode::LWA as u32 {
            Instruction::new(Opcode::LWA, 0, 0, 0, false, false)
        } else {
            Instruction::new(Opcode::PRECOMPILE, precompile_opcode, 0, 0, false, false)
        };
        instructions_new.push(instruction);
    }

    instructions_new
}
