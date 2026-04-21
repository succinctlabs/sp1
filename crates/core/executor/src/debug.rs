use sp1_jit::debug::State;

use crate::{Program, Register, SyscallCode, HALT_PC};

#[allow(unused)]
pub fn render_current_instruction(program: &Program, state: &State) -> String {
    if state.pc == HALT_PC {
        return "<HALTED>".to_string();
    }
    let Some(instruction) = program.fetch(state.pc) else {
        return format!("<INVALID_PC=0x{:016x}>", state.pc);
    };
    let a = instruction.op_a;
    let b = if instruction.imm_b {
        format!("0x{:016x} (imm) ", instruction.op_b as i32)
    } else {
        let index = instruction.op_b as usize;
        let value = state.registers[index];
        format!("0x{value:016x} (%x{index:02})")
    };
    let c = if instruction.imm_c {
        format!("0x{:016x} (imm) ", instruction.op_c as i32)
    } else {
        let index = instruction.op_c as usize;
        let value = state.registers[index];
        format!("0x{value:016x} (%x{index:02})")
    };

    let rd = if instruction.is_ecall_instruction() {
        let syscall_name =
            SyscallCode::from_u32(state.registers[Register::X5 as usize] as u32).to_string();
        syscall_name[..syscall_name.len().min(12)].to_string()
    } else {
        format!("%x{a:02}")
    };
    let pc = state.pc;
    let opcode = instruction.opcode.mnemonic();
    let clk = state.clk;
    format!("{clk:>12}  {pc:x} {opcode:>10}  {rd:>12}  {b}  {c}")
}

#[allow(unused)]
pub fn compare_states(program: &Program, got: &State, expected: &State) -> (bool, String) {
    use std::fmt::Write;

    let mut is_equal = true;
    let mut report = String::new();
    writeln!(report, "  REGISTER                     GOT              EXPECTED").unwrap();

    for i in 0..32 {
        let got = got.registers[i];
        let expected = expected.registers[i];
        if got == expected {
            writeln!(report, "        {i:>2}: ✅  0x{got:016x} == 0x{expected:016x}").unwrap();
        } else {
            writeln!(report, "        {i:>2}: ❌  0x{got:016x} != 0x{expected:016x}").unwrap();
            is_equal = false;
        }
    }

    if got.pc == expected.pc {
        writeln!(report, "        PC: ✅  0x{:016x} == 0x{:016x}", got.pc, expected.pc).unwrap();
    } else {
        writeln!(
            report,
            "        PC: ❌  0x{:016x} != 0x{:016x} (diff = {})",
            got.pc,
            expected.pc,
            got.pc as i64 - expected.pc as i64
        )
        .unwrap();
        is_equal = false;
    }

    if got.clk == expected.clk {
        writeln!(report, "       CLK: ✅  0x{:016x} == 0x{:016x}", got.clk, expected.clk).unwrap();
    } else {
        writeln!(
            report,
            "       CLK: ❌  0x{:016x} != 0x{:016x} (diff = {})",
            got.clk,
            expected.clk,
            got.clk as i64 - expected.clk as i64
        )
        .unwrap();
        is_equal = false;
    }

    if got.global_clk == expected.global_clk {
        writeln!(
            report,
            "GLOBAL_CLK: ✅  0x{:016x} == 0x{:016x}",
            got.global_clk, expected.global_clk
        )
        .unwrap();
    } else {
        writeln!(
            report,
            "GLOBAL_CLK: ❌  0x{:016x} != 0x{:016x} (diff = {})",
            got.global_clk,
            expected.global_clk,
            got.global_clk as i64 - expected.global_clk as i64
        )
        .unwrap();
        is_equal = false;
    }

    writeln!(report).unwrap();

    let got_instruction = render_current_instruction(program, got);
    let expected_instruction = render_current_instruction(program, expected);
    if got_instruction == expected_instruction {
        writeln!(report, "✅ CURRENT INSTRUCTION MATCHES").unwrap();
        writeln!(report, "       GOT: {got_instruction}").unwrap();
        writeln!(report, "  EXPECTED: {expected_instruction}").unwrap();
    } else {
        writeln!(report, "❌ CURRENT INSTRUCTION DOES NOT MATCH").unwrap();
        writeln!(report, "       GOT: {got_instruction}").unwrap();
        writeln!(report, "  EXPECTED: {expected_instruction}").unwrap();
        is_equal = false;
    }

    (is_equal, report)
}
