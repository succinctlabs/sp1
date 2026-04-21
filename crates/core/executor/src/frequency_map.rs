use std::sync::Arc;

use itertools::Itertools;
use powdr_autoprecompiles::execution_profile::ExecutionProfile;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::MinimalTrace;

use crate::{
    CoreVM, CycleResult, ExecutionError, MinimalExecutor, Opcode, Program, SP1Context, SP1CoreOpts,
};

/// Execute a program and count how many times each program counter is visited.
pub fn execute_for_frequency_map<'a>(
    program: &Arc<Program>,
    input: impl Iterator<Item = &'a [u8]>,
) -> Result<ExecutionProfile, ExecutionError> {
    let opts = SP1CoreOpts::default();
    let proof_nonce = SP1Context::default().proof_nonce;

    let mut minimal_executor =
        MinimalExecutor::tracing(program.clone(), opts.minimal_trace_chunk_threshold);

    for buf in input {
        minimal_executor.with_input(buf);
    }

    let mut pc_list = vec![];
    while let Some(chunk) = minimal_executor.execute_chunk() {
        let mut vm = PcListVm::new(&chunk, program.clone(), opts.clone(), proof_nonce);

        loop {
            match vm.execute_instruction(&mut pc_list)? {
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd => break,
                CycleResult::Done(true) => {
                    return Ok(ExecutionProfile {
                        pc_count: pc_list
                            .iter()
                            .copied()
                            .counts()
                            .into_iter()
                            .map(|(pc, count)| (pc, count as u32))
                            .collect(),
                        pc_list,
                    })
                }
                CycleResult::ShardBoundary => {
                    unreachable!("Shard boundaries are not expected in pure execution")
                }
            }
        }
    }

    Ok(ExecutionProfile {
        pc_count: pc_list
            .iter()
            .copied()
            .counts()
            .into_iter()
            .map(|(pc, count)| (pc, count as u32))
            .collect(),
        pc_list,
    })
}

struct PcListVm<'a> {
    core: CoreVM<'a, ()>,
}

impl<'a> PcListVm<'a> {
    fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
    ) -> Self {
        Self { core: CoreVM::new(trace, program, opts, proof_nonce) }
    }

    fn execute_instruction(
        &mut self,
        pc_list: &mut Vec<u64>,
    ) -> Result<CycleResult, ExecutionError> {
        pc_list.push(self.core.pc());

        let instruction = self.core.fetch(|| ());
        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        // SAFETY: The instruction is guaranteed to be valid as we checked for `is_none` above.
        let instruction = unsafe { *instruction.unwrap_unchecked() };

        match instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                let _ = self.core.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => {
                let _ = self.core.execute_load(&instruction)?;
            }
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                let _ = self.core.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                let _ = self.core.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                let _ = self.core.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                let _ = self.core.execute_utype(&instruction);
            }
            Opcode::ECALL => {
                let code = self.core.read_code();
                let _ = CoreVM::<()>::execute_ecall(&mut self.core, &instruction, code)?;
            }
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        let (res, calls) = self.core.advance(|| ());
        assert!(
            calls.is_empty(),
            "Frequency map collection should happen on the program with no apcs, but we found apc calls"
        );

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::{iter::empty, sync::Arc};
    use test_artifacts::FIBONACCI_ELF;

    use crate::{execute_for_frequency_map, Program};

    #[test]
    fn fibonacci_frequency_map() {
        let frequency_map =
            execute_for_frequency_map(&Arc::new(Program::from(&FIBONACCI_ELF).unwrap()), empty())
                .unwrap();
        assert!(!frequency_map.pc_count.is_empty());
    }
}
