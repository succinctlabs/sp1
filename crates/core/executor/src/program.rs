//! Programs that can be executed by the SP1 zkVM.

use std::{fs::File, io::Read, str::FromStr};

use crate::{
    disassembler::{transpile, Elf},
    instruction::Instruction,
    RiscvAirId,
};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use slop_algebra::{Field, PrimeField32};
use slop_maybe_rayon::prelude::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use sp1_hypercube::{
    air::{MachineAir, MachineProgram},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    shape::Shape,
    InteractionKind, UntrustedConfig,
};
use sp1_primitives::consts::split_page_idx;
use std::sync::Arc;

#[cfg(feature = "mprotect")]
use sp1_hypercube::addr_to_limbs;

/// The maximum number of instructions in a program.
pub const MAX_PROGRAM_SIZE: usize = 1 << 22;

/// A program that can be executed by the SP1 zkVM.
///
/// Contains a series of instructions along with the initial memory image. It also contains the
/// start address and base address of the program.
#[derive(Debug, Clone, Default, Serialize, Deserialize, deepsize2::DeepSizeOf)]
pub struct Program {
    /// The instructions of the program.
    pub instructions: Vec<Instruction>,
    /// The encoded instructions of the program. Only used if program is untrusted
    pub instructions_encoded: Option<Vec<u32>>,
    /// The start address of the program. It is absolute, meaning not relative to `pc_base`.
    pub pc_start_abs: u64,
    /// The base address of the program.
    pub pc_base: u64,
    /// The trap context address of the program.
    pub trap_context: Option<u64>,
    /// The initial page protection image, mapping page indices to protection flags.
    pub page_prot_image: HashMap<u64, u8>,
    /// The initial memory image, useful for global constants
    pub memory_image: Arc<HashMap<u64, u64>>,
    /// The shape for the preprocessed tables.
    pub preprocessed_shape: Option<Shape<RiscvAirId>>,
    /// Flag indicating if untrusted programs are allowed.
    pub enable_untrusted_programs: bool,
    /// Function symbols for profiling & debugging. In the form of (name, start address, size)
    pub function_symbols: Vec<(String, u64, u64)>,
    /// The memory region where untrusted program could live in. It is also the
    /// memory region mprotect works on.
    pub untrusted_memory: Option<(u64, u64)>,
    /// The profiler stack from a dump-elf/bootloader session.
    pub dump_elf_stack: Vec<u64>,
}

impl Program {
    /// Create a new [Program].
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start_abs: u64, pc_base: u64) -> Self {
        assert!(!instructions.is_empty(), "empty program not supported");
        assert!(instructions.len() <= (1 << 22), "program has too many instructions");

        Self {
            instructions,
            instructions_encoded: None,
            pc_start_abs,
            pc_base,
            trap_context: None,
            page_prot_image: HashMap::new(),
            memory_image: Arc::new(HashMap::new()),
            preprocessed_shape: None,
            enable_untrusted_programs: false,
            untrusted_memory: None,
            dump_elf_stack: Vec::new(),
            function_symbols: Vec::new(),
        }
    }

    /// Disassemble a RV64IM ELF to a program that be executed by the VM.
    ///
    /// # Errors
    ///
    /// This function may return an error if the ELF is not valid.
    pub fn from(input: &[u8]) -> eyre::Result<Self> {
        // Decode the bytes as an ELF.
        let elf = Elf::decode(input)?;

        if elf.pc_base < 32 {
            eyre::bail!("elf with pc_base < 32 is not supported");
        }
        if elf.pc_base % 4 != 0 {
            eyre::bail!("elf with pc_base not a multiple of 4 is not supported");
        }

        // Transpile the RV64IM instructions.
        let instruction_pair = transpile(&elf.instructions, false);
        let (instructions, instructions_encoded): (Vec<Instruction>, Vec<u32>) =
            instruction_pair.into_iter().unzip();

        if instructions.is_empty() {
            eyre::bail!("empty elf not supported");
        }
        if instructions.len() > (1 << 22) {
            eyre::bail!("elf has too many instructions");
        }

        let enable_untrusted_programs = elf.untrusted_memory.is_some();
        // Return the program.
        Ok(Program {
            instructions,
            instructions_encoded: Some(instructions_encoded),
            pc_start_abs: elf.pc_start,
            pc_base: elf.pc_base,
            trap_context: elf.trap_context,
            memory_image: elf.memory_image,
            page_prot_image: elf.page_prot_image,
            preprocessed_shape: None,
            enable_untrusted_programs,
            function_symbols: elf.function_symbols,
            untrusted_memory: elf.untrusted_memory,
            dump_elf_stack: elf.dump_elf_stack,
        })
    }

    /// Disassemble a RV64IM ELF to a program that be executed by the VM from a file path.
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
        let id = RiscvAirId::from_str(air.name()).unwrap();
        self.preprocessed_shape.as_ref().map(|shape| {
            shape
                .log2_height(&id)
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    #[must_use]
    /// Fetch the instruction at the given program counter.
    pub fn fetch(&self, pc: u64) -> Option<&Instruction> {
        let idx = ((pc - self.pc_base) / 4) as usize;
        self.instructions.get(idx)
    }
}

impl<F: PrimeField32> MachineProgram<F> for Program {
    fn pc_start(&self) -> [F; 3] {
        [
            F::from_canonical_u16((self.pc_start_abs & 0xFFFF) as u16),
            F::from_canonical_u16(((self.pc_start_abs >> 16) & 0xFFFF) as u16),
            F::from_canonical_u16(((self.pc_start_abs >> 32) & 0xFFFF) as u16),
        ]
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        let mut memory_digests: Vec<SepticCurveComplete<F>> = self
            .memory_image
            .iter()
            .par_bridge()
            .map(|(&addr, &word)| {
                let limb_1 = (word & 0xFFFF) as u32 + (1 << 16) * ((word >> 32) & 0xFF) as u32;
                let limb_2 =
                    ((word >> 16) & 0xFFFF) as u32 + (1 << 16) * ((word >> 40) & 0xFF) as u32;
                let values = [
                    (InteractionKind::Memory as u32) << 24,
                    0,
                    (addr & 0xFFFF) as u32,
                    ((addr >> 16) & 0xFFFF) as u32,
                    ((addr >> 32) & 0xFFFF) as u32,
                    limb_1,
                    limb_2,
                    ((word >> 48) & 0xFFFF) as u32,
                ];
                let (point, _, _, _) =
                    SepticCurve::<F>::lift_x(values.map(|x| F::from_canonical_u32(x)));
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();

        if self.enable_untrusted_programs {
            let page_prot_digests: Vec<SepticCurveComplete<F>> = self
                .page_prot_image
                .iter()
                .par_bridge()
                .map(|(&page_idx, &page_prot)| {
                    // Use exact same encoding as PageProtGlobalChip Initialize events
                    let page_idx_limbs = split_page_idx(page_idx);
                    let values = [
                        (InteractionKind::PageProtAccess as u32) << 24,
                        0,
                        page_idx_limbs[0].into(),
                        page_idx_limbs[1].into(),
                        page_idx_limbs[2].into(),
                        page_prot.into(),
                        0,
                        0,
                    ];
                    let (point, _, _, _) =
                        SepticCurve::<F>::lift_x(values.map(|x| F::from_canonical_u32(x)));
                    SepticCurveComplete::Affine(point.neg())
                })
                .collect();

            // Combine both memory and page protection contributions.
            memory_digests.extend(page_prot_digests);
        }

        memory_digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            memory_digests
                .into_par_iter()
                .reduce(|| SepticCurveComplete::Infinity, |a, b| a + b)
                .point(),
        )
    }

    fn untrusted_config(&self) -> UntrustedConfig<F> {
        UntrustedConfig {
            enable_untrusted_programs: F::from_bool(self.enable_untrusted_programs),
            #[cfg(feature = "mprotect")]
            enable_trap_handler: F::from_bool(self.trap_context.is_some()),
            #[cfg(feature = "mprotect")]
            trap_context: self.trap_context.map_or([[F::zero(); 3]; 3], |addr| {
                [addr_to_limbs(addr), addr_to_limbs(addr + 8), addr_to_limbs(addr + 16)]
            }),
            #[cfg(feature = "mprotect")]
            untrusted_memory: self.untrusted_memory.map_or([[F::zero(); 3]; 2], |(start, end)| {
                [addr_to_limbs(start), addr_to_limbs(end)]
            }),
        }
    }
}
