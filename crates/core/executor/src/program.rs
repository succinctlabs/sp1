//! Programs that can be executed by the SP1 zkVM.

use std::{fs::File, io::Read, str::FromStr};

use crate::{
    disassembler::{transpile, Elf},
    instruction::Instruction,
    RiscvAirId,
};
use hashbrown::HashMap;
use powdr_autoprecompiles::execution::{ExecutionState, OptimisticConstraints};
use serde::{Deserialize, Serialize};
use slop_algebra::{Field, PrimeField32};
use slop_maybe_rayon::prelude::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use sp1_hypercube::{
    air::{MachineAir, MachineProgram},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    shape::Shape,
    InteractionKind, Machine,
};
use sp1_primitives::consts::split_page_idx;
use std::sync::Arc;

/// Cost of APC, currently defined as number of columns.
pub type ApcCost = u64;
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
    /// The data about the apcs
    pub apcs: Apcs,
}

/// Data about the apcs of this program, used during execution
#[derive(Debug, Clone, Default, Serialize, Deserialize, deepsize2::DeepSizeOf)]
pub struct Apcs {
    /// The ranges of instructions that have APC chips. The values are indices in `apc_by_index`
    pub apc_indices_by_start_idx: HashMap<usize, Vec<usize>>,
    /// The details of each APC
    pub apc_by_index: Vec<Apc>,
}

impl Apcs {
    fn add(&mut self, apc: Apc) {
        let index = self.apc_by_index.len();
        self.apc_indices_by_start_idx.entry(apc.start_pc_idx).or_default().push(index);
        self.apc_by_index.push(apc);
    }

    fn get(&self, index: usize) -> Option<&[usize]> {
        self.apc_indices_by_start_idx.get(&index).map(std::vec::Vec::as_slice)
    }
}

/// Represents an APC in the program, which is a range for which the prover can choose to run an
/// alternative implementation.
#[derive(Debug, Clone, Serialize, Deserialize, deepsize2::DeepSizeOf)]
pub struct Apc {
    /// The index of the pc at which this APC starts
    start_pc_idx: usize,
    /// The number of cycles required to go through this APC
    cycle_count: usize,
    /// The cost for this APC
    cost: ApcCost,
    /// The execution constraints for this APC
    execution_constraints: OptimisticConstraints<u8, u64>,
}

impl Apc {
    /// Create a new apc for a given range, cost, and execution constraints.
    pub fn new<R: Into<ApcRange>>(
        range: R,
        cost: u64,
        execution_constraints: OptimisticConstraints<u8, u64>,
    ) -> Self {
        let range = range.into();
        Self {
            start_pc_idx: range.start().unwrap(),
            cycle_count: range.len(),
            cost,
            execution_constraints,
        }
    }

    /// Return the cost of this apc.
    #[must_use]
    pub fn cost(&self) -> ApcCost {
        self.cost
    }
}

impl<S: ExecutionState<RegisterAddress = u8, Value = u64>> powdr_autoprecompiles::execution::Apc<S>
    for Apc
{
    fn cycle_count(&self) -> usize {
        self.cycle_count
    }

    fn priority(&self) -> usize {
        // TODO: encode priority coming from saved cells
        1
    }

    fn optimistic_constraints(&self) -> &OptimisticConstraints<u8, u64> {
        &self.execution_constraints
    }
}

/// Represents a APC range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, deepsize2::DeepSizeOf)]
pub struct ApcRange {
    start_idx: usize,
    len: usize,
}

impl ApcRange {
    /// Create a new range from a start index and a length
    #[must_use]
    pub fn new(start_idx: usize, len: usize) -> Self {
        Self { start_idx, len }
    }

    /// Returns the first value included in the range
    #[must_use]
    pub fn start(&self) -> Option<usize> {
        if self.len > 0 {
            Some(self.start_idx)
        } else {
            None
        }
    }

    /// Returns the last value included in the range
    #[must_use]
    pub fn end(&self) -> Option<usize> {
        if self.len > 0 {
            Some(self.start_idx + self.len - 1)
        } else {
            None
        }
    }

    /// Returns the length of the range
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the range is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Convert a rust range (upper exclusive) to an APC range.
impl From<&(usize, usize)> for ApcRange {
    fn from((start, end): &(usize, usize)) -> Self {
        Self::new(*start, *end - *start)
    }
}

impl Program {
    /// Add apcs to this program
    #[must_use]
    pub fn with_apcs(self, apc_ranges_and_costs: impl IntoIterator<Item = Apc>) -> Self {
        apc_ranges_and_costs.into_iter().fold(self, Program::add_apc)
    }

    /// Add an APC range to the program.
    #[must_use]
    pub fn add_apc(mut self, apc: Apc) -> Self {
        self.apcs.add(apc);
        self
    }

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
            page_prot_image: HashMap::new(),
            memory_image: Arc::new(HashMap::new()),
            preprocessed_shape: None,
            enable_untrusted_programs: false,
            function_symbols: Vec::new(),
            apcs: Apcs::default(),
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
        let instruction_pair = transpile(&elf.instructions);
        let (instructions, instructions_encoded): (Vec<Instruction>, Vec<u32>) =
            instruction_pair.into_iter().unzip();

        if instructions.is_empty() {
            eyre::bail!("empty elf not supported");
        }
        if instructions.len() > (1 << 22) {
            eyre::bail!("elf has too many instructions");
        }

        // Return the program.
        Ok(Program {
            instructions,
            instructions_encoded: Some(instructions_encoded),
            pc_start_abs: elf.pc_start,
            pc_base: elf.pc_base,
            memory_image: elf.memory_image,
            page_prot_image: elf.page_prot_image,
            preprocessed_shape: None,
            enable_untrusted_programs: elf.enable_untrusted_programs,
            function_symbols: elf.function_symbols,
            apcs: Apcs::default(),
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

    /// Create a program and customize it with a machine. This means that the apcs of the machine are added to the program to be available during execution.
    pub fn custom<F: Field>(
        input: &[u8],
        machine: &Machine<F, impl MachineAir<F, Program = Self>>,
    ) -> eyre::Result<Self> {
        // Return the program after customization by the machine
        Self::from(input).map(|p| machine.customize_program(p))
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

    #[must_use]
    /// Fetch the instruction at the given program counter, as well as the apc ranges, if any.
    pub fn fetch_with_apcs(&self, pc: u64) -> Option<(&Instruction, Option<&[usize]>)> {
        let idx = ((pc - self.pc_base) / 4) as usize;
        if idx < self.instructions.len() {
            Some((&self.instructions[idx], self.apcs.get(idx)))
        } else {
            None
        }
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

    fn enable_untrusted_programs(&self) -> F {
        F::from_bool(self.enable_untrusted_programs)
    }
}
