//! Programs that can be executed by the SP1 zkVM.

use std::{fs::File, io::Read, str::FromStr};

use crate::{
    disassembler::{transpile, Elf},
    instruction::Instruction,
    RiscvAirId,
};
use hashbrown::HashMap;
use p3_field::Field;
use p3_field::{AbstractExtensionField, PrimeField32};
use p3_maybe_rayon::prelude::IntoParallelIterator;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use sp1_stark::septic_curve::{SepticCurve, SepticCurveComplete};
use sp1_stark::septic_digest::SepticDigest;
use sp1_stark::septic_extension::SepticExtension;
use sp1_stark::InteractionKind;
use sp1_stark::{
    air::{MachineAir, MachineProgram},
    shape::Shape,
};

/// A program that can be executed by the SP1 zkVM.
///
/// Contains a series of instructions along with the initial memory image. It also contains the
/// start address and base address of the program.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Program {
    /// The instructions of the program.
    pub instructions: Vec<Instruction>,
    /// The start address of the program.
    pub pc_start: u32,
    /// The base address of the program.
    pub pc_base: u32,
    /// The initial memory image, useful for global constants.
    pub memory_image: HashMap<u32, u32>,
    /// The shape for the preprocessed tables.
    pub preprocessed_shape: Option<Shape<RiscvAirId>>,
}

impl Program {
    /// Create a new [Program].
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start: u32, pc_base: u32) -> Self {
        Self {
            instructions,
            pc_start,
            pc_base,
            memory_image: HashMap::new(),
            preprocessed_shape: None,
        }
    }

    /// Disassemble a RV32IM ELF to a program that be executed by the VM.
    ///
    /// # Errors
    ///
    /// This function may return an error if the ELF is not valid.
    pub fn from(input: &[u8]) -> eyre::Result<Self> {
        // Decode the bytes as an ELF.
        let elf = Elf::decode(input)?;

        // Transpile the RV32IM instructions.
        let instructions = transpile(&elf.instructions);

        // Return the program.
        Ok(Program {
            instructions,
            pc_start: elf.pc_start,
            pc_base: elf.pc_base,
            memory_image: elf.memory_image,
            preprocessed_shape: None,
        })
    }

    /// Disassemble a RV32IM ELF to a program that be executed by the VM from a file path.
    ///
    /// # Errors
    ///
    /// This function will return an error if the file cannot be opened or read.
    pub fn from_elf(path: &str) -> eyre::Result<Self> {
        let mut elf_code = Vec::new();
        File::open(path)?.read_to_end(&mut elf_code)?;
        Program::from(&elf_code)
    }

    /// Custom logic for padding the trace to a power of two according to the proof shape.
    pub fn fixed_log2_rows<F: Field, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        let id = RiscvAirId::from_str(&air.name()).unwrap();
        self.preprocessed_shape.as_ref().map(|shape| {
            shape
                .log2_height(&id)
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    #[must_use]
    /// Fetch the instruction at the given program counter.
    pub fn fetch(&self, pc: u32) -> &Instruction {
        let idx = ((pc - self.pc_base) / 4) as usize;
        &self.instructions[idx]
    }
}

impl<F: PrimeField32> MachineProgram<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        let mut digests: Vec<SepticCurveComplete<F>> = self
            .memory_image
            .iter()
            .par_bridge()
            .map(|(&addr, &word)| {
                let values = [
                    (InteractionKind::Memory as u32) << 16,
                    0,
                    addr,
                    word & 255,
                    (word >> 8) & 255,
                    (word >> 16) & 255,
                    (word >> 24) & 255,
                ];
                let x_start =
                    SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values[i]));
                let (point, _, _, _) = SepticCurve::<F>::lift_x(x_start);
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();
        digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            digests.into_par_iter().reduce(|| SepticCurveComplete::Infinity, |a, b| a + b).point(),
        )
    }
}
