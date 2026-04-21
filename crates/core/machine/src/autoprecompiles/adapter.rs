use std::{fmt::Display, sync::Arc};

use crate::autoprecompiles::{
    bus_interaction_handler::Sp1BusInteractionHandler, bus_map::Sp1SpecificBuses,
    instruction::Sp1Instruction, instruction_handler::Sp1InstructionHandler,
    memory_bus_interaction::Sp1MemoryBusInteraction, program::Sp1Program,
};
use powdr_autoprecompiles::{
    adapter::{Adapter, AdapterApc},
    evaluation::{AirStats, EvaluationResult},
};
use powdr_number::{FieldElement, LargeInt};
use slop_algebra::{AbstractField, PrimeField32};
use sp1_core_executor::{CoreExecutionState, Opcode};
use sp1_primitives::SP1Field;
use std::hash::Hash;
pub struct Sp1ApcAdapter;

impl Adapter for Sp1ApcAdapter {
    type Field = SP1Field;
    type PowdrField = powdr_number::KoalaBearField;
    type InstructionHandler = Sp1InstructionHandler<Self::Field>;
    type BusInteractionHandler = Sp1BusInteractionHandler;
    type Program = Sp1Program;
    type Instruction = Sp1Instruction;
    type MemoryBusInteraction<V: Ord + Clone + Eq + Display + Hash> = Sp1MemoryBusInteraction<V>;
    type CustomBusTypes = Sp1SpecificBuses;
    type ApcStats = EvaluationResult;
    type AirId = usize;
    type ExecutionState = CoreExecutionState;

    fn into_field(e: Self::PowdrField) -> Self::Field {
        Self::Field::from_canonical_u32(e.to_integer().try_into_u32().unwrap())
    }

    fn from_field(e: Self::Field) -> Self::PowdrField {
        Self::PowdrField::from_bytes_le(&e.as_canonical_u32().to_le_bytes())
    }

    fn apc_stats(
        apc: Arc<AdapterApc<Self>>,
        instruction_handler: &Self::InstructionHandler,
    ) -> Self::ApcStats {
        let stats_before = apc
            .block
            .instructions()
            .map(|s| *instruction_handler.get_instruction_air_stats(s).unwrap())
            .sum();
        let stats_after = AirStats::new(apc.machine());

        EvaluationResult { before: stats_before, after: stats_after }
    }

    fn is_allowed(instruction: &Self::Instruction) -> bool {
        !matches!(instruction.0.opcode, Opcode::EBREAK | Opcode::ECALL | Opcode::UNIMP)
    }

    fn is_branching(instruction: &Self::Instruction) -> bool {
        // We define the branch opcodes manually
        matches!(
            instruction.0.opcode,
            Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU
                | Opcode::JAL
                | Opcode::JALR
        )
    }
}
