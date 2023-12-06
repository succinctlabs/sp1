use super::Runtime;
use crate::alu::{Alu, AluOperation};
use crate::runtime::store::Event;
use crate::{
    cpu::Cpu,
    program::{
        base::{BaseISA, BaseInstruction},
        ISA,
    },
    runtime::store::Store,
};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct BaseRuntime {
    program: Vec<BaseInstruction>,
}

impl<S: Store> Runtime<BaseISA, S> for BaseRuntime {
    fn get_next_instruction(&self, store: &mut S) -> Option<<BaseISA as ISA>::Instruction> {
        let pc = *store.pc() as usize;
        self.program.get(pc).copied()
    }

    fn execute(
        &self,
        instruction: &<BaseISA as ISA>::Instruction,
        store: &mut S,
    ) -> Result<<S as Store>::Event> {
        let event = match instruction {
            BaseInstruction::SW(a, b) => {
                // Load the value from address fp-b into address fp-a.
                let fp = *store.fp();
                let addr_b = fp as usize + *b as usize;
                let b_bytes: [_; 4] = store.memory()[addr_b..addr_b + 4].try_into().unwrap();
                let addr_a = fp as usize + *a as usize;
                store.memory()[addr_a..addr_a + 4].copy_from_slice(&b_bytes);

                // Update the store state.
                *store.pc() += 1;
                *store.clk() += 1;

                // Record the event.
                let (opcode, arg1, arg2, arg3, imm) = BaseISA::decode(instruction);
                let cpu = Cpu {
                    clk: *store.clk(),
                    pc: *store.pc(),
                    fp: *store.fp(),
                    opcode,
                    arg1,
                    arg2,
                    arg3,
                    imm,
                };
                S::Event::core(cpu)
            }
            BaseInstruction::CW(a, b) => {
                // Store the constant word into address fp-a.
                let fp = *store.fp();
                let addr_a = fp as usize + *a as usize;
                store.memory()[addr_a..addr_a + 4].copy_from_slice(&b.to_le_bytes());

                // Update the store state.
                *store.pc() += 1;
                *store.clk() += 1;

                // Record the event.
                let (opcode, arg1, arg2, arg3, imm) = BaseISA::decode(instruction);
                let cpu = Cpu {
                    clk: *store.clk(),
                    pc: *store.pc(),
                    fp: *store.fp(),
                    opcode,
                    arg1,
                    arg2,
                    arg3,
                    imm,
                };
                S::Event::core(cpu)
            }
            BaseInstruction::XOR(a, b, c) => {
                // Bitwise XORs the values at address fp-b and fp-c and stores the result in fp-a.
                let fp = *store.fp();
                let addr_b = fp as usize + *b as usize;
                let addr_c = fp as usize + *c as usize;
                let v_b =
                    u32::from_le_bytes(store.memory()[addr_b..addr_b + 4].try_into().unwrap());
                let v_c =
                    u32::from_le_bytes(store.memory()[addr_c..addr_c + 4].try_into().unwrap());
                let v_a = v_b ^ v_c;
                let addr_a = fp as usize + *a as usize;
                store.memory()[addr_a..addr_a + 4].copy_from_slice(&v_a.to_le_bytes());

                // Update the store state.
                *store.pc() += 1;
                *store.clk() += 1;

                // Record the event.
                let (opcode, arg1, arg2, arg3, imm) = BaseISA::decode(instruction);
                let cpu = Cpu {
                    clk: *store.clk(),
                    pc: *store.pc(),
                    fp: *store.fp(),
                    opcode,
                    arg1,
                    arg2,
                    arg3,
                    imm,
                };
                let alu = Alu {
                    op: AluOperation::Xor,
                    v_a,
                    v_b,
                    v_c,
                };
                S::Event::alu(cpu, alu)
            }
            _ => unimplemented!("Instrcution not implemented"),
        };
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use crate::program::base::BaseInstruction;

    #[test]
    fn test_basic_rt() {
        let program = vec![
            BaseInstruction::CW(0, 0),
            BaseInstruction::CW(1, 1),
            BaseInstruction::CW(2, 2),
            BaseInstruction::XOR(3, 1, 2),
            BaseInstruction::SW(0, 3),
        ];
    }
}
