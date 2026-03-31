use std::collections::BTreeMap;

use crate::{
    autoprecompiles::{
        air_to_symbolic_machine::{
            air_to_symbolic_machine, constrain_is_trusted_to_one, sort_memory_interactions,
        },
        instruction::Sp1Instruction,
        DEFAULT_DEGREE_BOUND,
    },
    riscv::RiscvAirWithoutApcs,
};
use itertools::Itertools;
use powdr_autoprecompiles::{
    evaluation::AirStats, symbolic_machine::SymbolicMachine, DegreeBound, InstructionHandler,
};
use slop_algebra::PrimeField32;
use sp1_core_executor::{Opcode, Register, RiscvAirId};
use sp1_hypercube::air::MachineAir;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstructionType {
    /// An instruction that is not a load to X0, represented by its opcode.
    NonLoadX0(Opcode),
    /// A load instruction that is a load to x0.
    LoadX0,
}

impl From<sp1_core_executor::Instruction> for InstructionType {
    fn from(instruction: sp1_core_executor::Instruction) -> Self {
        if is_load_opcode(instruction.opcode) && instruction.op_a == Register::X0 as u8 {
            InstructionType::LoadX0
        } else {
            InstructionType::NonLoadX0(instruction.opcode)
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Sp1InstructionHandler<F> {
    /// All instruction AIRs.
    airs: Vec<(SymbolicMachine<F>, AirStats)>,
    /// Maps (opcode, op_a_0) to the index of the corresponding AIR in `airs`.
    /// (Using BTreeMap for determinism of [Sp1InstructionHandler::airs].)
    instruction_to_air_idx: BTreeMap<InstructionType, usize>,
}

impl<F: PrimeField32> Sp1InstructionHandler<F> {
    pub fn new() -> Self {
        let mut handler = Self::default();
        for air in RiscvAirWithoutApcs::airs() {
            handler.add(&air);
        }
        handler
    }

    pub fn add(&mut self, riscv_air: &RiscvAirWithoutApcs<F>) {
        let opcodes = air_id_to_opcodes(riscv_air.id());

        if opcodes.is_empty() {
            // Not an instruction AIR.
            return;
        }
        let machine = match air_to_symbolic_machine(riscv_air, &mut None) {
            Ok(machine) => machine,
            Err(err) => {
                tracing::warn!("Failed to convert {} to symbolic machine: {err}", riscv_air.name());
                return;
            }
        };

        let machine = sort_memory_interactions(machine);
        let machine = constrain_is_trusted_to_one(machine);

        let instruction_types = if riscv_air.id() == RiscvAirId::LoadX0 {
            // For loads, LoadX0 handles all loads if rd == x0
            vec![InstructionType::LoadX0]
        } else {
            opcodes.into_iter().map(InstructionType::NonLoadX0).collect_vec()
        };

        let idx = self.airs.len();
        // Cache stats of original airs so that we don't repeatedly calculated them during PGO.
        let air_stats = AirStats::new(&machine);
        self.airs.push((machine, air_stats));

        for instruction_type in instruction_types {
            self.instruction_to_air_idx.insert(instruction_type, idx);
        }
    }

    pub fn air_count(&self) -> usize {
        self.airs.len()
    }

    pub fn get_instruction_air_and_stats(
        &self,
        instruction: &Sp1Instruction,
    ) -> Option<(usize, &(SymbolicMachine<F>, AirStats))> {
        let instruction_type = InstructionType::from(instruction.0);

        let idx = self.instruction_to_air_idx.get(&instruction_type)?;
        Some((*idx, &self.airs[*idx]))
    }

    pub fn get_instruction_air_stats(&self, instruction: &Sp1Instruction) -> Option<&AirStats> {
        self.get_instruction_air_and_stats(instruction).map(|(_, (_, stats))| stats)
    }

    #[cfg(test)]
    pub fn airs(&self) -> impl Iterator<Item = (InstructionType, &SymbolicMachine<F>)> {
        self.instruction_to_air_idx
            .iter()
            .map(|(instruction_type, idx)| (instruction_type.clone(), &self.airs[*idx].0))
    }
}

fn air_id_to_opcodes(air_id: RiscvAirId) -> Vec<Opcode> {
    // AIR -> Opcode mapping inspired from:
    // https://github.com/succinctlabs/sp1-wip/blob/1ec34e044ead850ed90deb1b66771eb0cfc8dc7e/crates/core/executor/src/executor.rs#L2552
    match air_id {
        RiscvAirId::Add => vec![Opcode::ADD],
        RiscvAirId::Addi => vec![Opcode::ADDI],
        RiscvAirId::Addw => vec![Opcode::ADDW],
        RiscvAirId::Sub => vec![Opcode::SUB],
        RiscvAirId::Subw => vec![Opcode::SUBW],
        RiscvAirId::Bitwise => vec![Opcode::XOR, Opcode::OR, Opcode::AND],
        RiscvAirId::DivRem => vec![
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
            Opcode::DIVW,
            Opcode::DIVUW,
            Opcode::REMW,
            Opcode::REMUW,
        ],
        RiscvAirId::Lt => vec![Opcode::SLT, Opcode::SLTU],
        RiscvAirId::Mul => {
            vec![Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU, Opcode::MULW]
        }
        RiscvAirId::ShiftLeft => vec![Opcode::SLL, Opcode::SLLW],
        RiscvAirId::ShiftRight => vec![Opcode::SRL, Opcode::SRA, Opcode::SRLW, Opcode::SRAW],
        RiscvAirId::Branch => {
            vec![Opcode::BEQ, Opcode::BNE, Opcode::BLT, Opcode::BGE, Opcode::BLTU, Opcode::BGEU]
        }
        RiscvAirId::Jal => vec![Opcode::JAL],
        RiscvAirId::Jalr => vec![Opcode::JALR],
        RiscvAirId::UType => vec![Opcode::LUI, Opcode::AUIPC],
        RiscvAirId::LoadByte => vec![Opcode::LB, Opcode::LBU],
        RiscvAirId::LoadHalf => vec![Opcode::LH, Opcode::LHU],
        RiscvAirId::LoadWord => vec![Opcode::LW, Opcode::LWU],
        RiscvAirId::LoadDouble => vec![Opcode::LD],
        // Note that for load instructions, the opcode -> AIR mapping is not injective.
        RiscvAirId::LoadX0 => vec![
            Opcode::LB,
            Opcode::LBU,
            Opcode::LH,
            Opcode::LHU,
            Opcode::LW,
            Opcode::LWU,
            Opcode::LD,
        ],
        RiscvAirId::StoreByte => vec![Opcode::SB],
        RiscvAirId::StoreHalf => vec![Opcode::SH],
        RiscvAirId::StoreWord => vec![Opcode::SW],
        RiscvAirId::StoreDouble => vec![Opcode::SD],
        _ => Default::default(),
    }
}

pub fn try_instruction_type_to_air_id(instruction_type: InstructionType) -> Option<RiscvAirId> {
    match instruction_type {
        InstructionType::NonLoadX0(opcode) => match opcode {
            Opcode::ADD => Some(RiscvAirId::Add),
            Opcode::ADDI => Some(RiscvAirId::Addi),
            Opcode::SUB => Some(RiscvAirId::Sub),
            Opcode::XOR | Opcode::OR | Opcode::AND => Some(RiscvAirId::Bitwise),
            Opcode::SLL | Opcode::SLLW => Some(RiscvAirId::ShiftLeft),
            Opcode::SRL | Opcode::SRA | Opcode::SRLW | Opcode::SRAW => Some(RiscvAirId::ShiftRight),
            Opcode::SLT | Opcode::SLTU => Some(RiscvAirId::Lt),
            Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU | Opcode::MULW => {
                Some(RiscvAirId::Mul)
            }
            Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMW
            | Opcode::REMUW => Some(RiscvAirId::DivRem),
            Opcode::LB | Opcode::LBU => Some(RiscvAirId::LoadByte),
            Opcode::LH | Opcode::LHU => Some(RiscvAirId::LoadHalf),
            Opcode::LW | Opcode::LWU => Some(RiscvAirId::LoadWord),
            Opcode::LD => Some(RiscvAirId::LoadDouble),
            Opcode::SB => Some(RiscvAirId::StoreByte),
            Opcode::SH => Some(RiscvAirId::StoreHalf),
            Opcode::SW => Some(RiscvAirId::StoreWord),
            Opcode::SD => Some(RiscvAirId::StoreDouble),
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                Some(RiscvAirId::Branch)
            }
            Opcode::JAL => Some(RiscvAirId::Jal),
            Opcode::JALR => Some(RiscvAirId::Jalr),
            Opcode::AUIPC | Opcode::LUI => Some(RiscvAirId::UType),
            Opcode::ECALL => None,
            Opcode::EBREAK => None,
            Opcode::ADDW => Some(RiscvAirId::Addw),
            Opcode::SUBW => Some(RiscvAirId::Subw),
            Opcode::UNIMP => None,
        },
        InstructionType::LoadX0 => Some(RiscvAirId::LoadX0),
    }
}

fn is_load_opcode(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW | Opcode::LWU | Opcode::LD
    )
}

impl<F: PrimeField32> InstructionHandler for Sp1InstructionHandler<F> {
    type Field = F;

    type Instruction = Sp1Instruction;

    type AirId = usize;

    fn get_instruction_air_and_id(
        &self,
        instruction: &Sp1Instruction,
    ) -> (usize, &SymbolicMachine<F>) {
        self.get_instruction_air_and_stats(instruction)
            .map(|(id, (machine, _))| (id, machine))
            .unwrap()
    }

    fn get_instruction_air_stats(&self, instruction: &Sp1Instruction) -> AirStats {
        self.get_instruction_air_and_stats(instruction)
            .map(|(_, (_, stats))| stats)
            .copied()
            .unwrap()
    }

    fn degree_bound(&self) -> DegreeBound {
        DEFAULT_DEGREE_BOUND
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    fn air_id_to_opcode_to_air_id() {
        for air_id in RiscvAirId::iter() {
            let instruction_types = if air_id == RiscvAirId::LoadX0 {
                vec![InstructionType::LoadX0]
            } else {
                air_id_to_opcodes(air_id).into_iter().map(InstructionType::NonLoadX0).collect_vec()
            };
            for instruction_type in instruction_types {
                assert_eq!(try_instruction_type_to_air_id(instruction_type), Some(air_id));
            }
        }
    }
}
