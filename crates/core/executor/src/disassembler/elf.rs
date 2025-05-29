use std::cmp::min;

use elf::{
    abi::{EM_RISCV, ET_EXEC, PF_W, PF_X, PT_LOAD},
    endian::LittleEndian,
    file::Class,
    ElfBytes,
};
use eyre::OptionExt;
use hashbrown::HashMap;
use sp1_primitives::consts::{BABYBEAR_PRIME, MAXIMUM_MEMORY_SIZE, WORD_SIZE};

/// RISC-V 32IM ELF (Executable and Linkable Format) File.
///
/// This file represents a binary in the ELF format, specifically the RISC-V 32IM architecture
/// with the following extensions:
///
/// - Base Integer Instruction Set (I)
/// - Integer Multiplication and Division (M)
///
/// This format is commonly used in embedded systems and is supported by many compilers.
#[derive(Debug, Clone)]
pub(crate) struct Elf {
    /// The instructions of the program encoded as 32-bits.
    pub(crate) instructions: Vec<u32>,
    /// The start address of the program.
    pub(crate) pc_start: u32,
    /// The base address of the program.
    pub(crate) pc_base: u32,
    /// The initial memory image, useful for global constants.
    pub(crate) memory_image: HashMap<u32, u32>,
}

impl Elf {
    /// Create a new [Elf].
    #[must_use]
    pub(crate) const fn new(
        instructions: Vec<u32>,
        pc_start: u32,
        pc_base: u32,
        memory_image: HashMap<u32, u32>,
    ) -> Self {
        Self { instructions, pc_start, pc_base, memory_image }
    }

    /// Parse the ELF file into a vector of 32-bit encoded instructions and the first memory
    /// address.
    ///
    /// # Errors
    ///
    /// This function may return an error if the ELF is not valid.
    ///
    /// Reference: [Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
    #[allow(clippy::too_many_lines)]
    pub(crate) fn decode(input: &[u8]) -> eyre::Result<Self> {
        let mut image: HashMap<u32, u32> = HashMap::new();

        // Parse the ELF file assuming that it is little-endian..
        let elf = ElfBytes::<LittleEndian>::minimal_parse(input)?;

        // Some sanity checks to make sure that the ELF file is valid.
        if elf.ehdr.class != Class::ELF32 {
            eyre::bail!("must be a 32-bit elf");
        } else if elf.ehdr.e_machine != EM_RISCV {
            eyre::bail!("must be a riscv machine");
        } else if elf.ehdr.e_type != ET_EXEC {
            eyre::bail!("must be executable");
        }

        // Get the entrypoint of the ELF file as an u32.
        let entry: u32 = elf.ehdr.e_entry.try_into()?;

        // Make sure the entrypoint is valid.
        if entry == MAXIMUM_MEMORY_SIZE || entry % WORD_SIZE as u32 != 0 {
            eyre::bail!("invalid entrypoint");
        }

        // Get the segments of the ELF file.
        let segments = elf.segments().ok_or_else(|| eyre::eyre!("failed to get segments"))?;
        if segments.len() > 256 {
            eyre::bail!("too many program headers");
        }

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = None;

        // Data about the last segment.
        let mut prev_segment_end_addr = None;

        // Check that the segments are sorted and disjoint.
        // Only read segments that are executable instructions that are also PT_LOAD.
        for segment in segments.iter().filter(|x| x.p_type == PT_LOAD) {
            // Get the file size of the segment as an u32.
            let file_size: u32 = segment.p_filesz.try_into()?;
            if file_size == MAXIMUM_MEMORY_SIZE {
                eyre::bail!("invalid segment file_size");
            }

            // Get the memory size of the segment as an u32.
            let mem_size: u32 = segment.p_memsz.try_into()?;
            if mem_size == MAXIMUM_MEMORY_SIZE {
                eyre::bail!("Invalid segment mem_size");
            }

            // Get the virtual address of the segment as an u32.
            let vaddr: u32 = segment.p_vaddr.try_into()?;
            if vaddr % WORD_SIZE as u32 != 0 {
                eyre::bail!("vaddr {vaddr:08x} is unaligned");
            }
            if vaddr < 0x00200800 {
                eprintln!("detected old compiler flags: recompile the ELF for additional security");
                for sh in elf
                    .section_headers()
                    .ok_or_else(|| eyre::eyre!("failed to get section headers"))?
                {
                    let sec_start = sh.sh_addr;
                    let seg_start = segment.p_vaddr;
                    if sec_start < seg_start + segment.p_filesz &&
                        seg_start < sec_start + sh.sh_size &&
                        (sh.sh_type == 1 || sh.sh_type == 8)
                    {
                        eyre::bail!("program data is not allowed to overlap with program headers with vaddr < 0x00200800");
                    }
                }
            }

            if (segment.p_flags & PF_X) != 0 && (segment.p_flags & PF_W) != 0 {
                eyre::bail!("ELF has a segment that is both writable and executable");
            }

            // Check that the ELF structure is supported.
            if let Some(last_addr) = prev_segment_end_addr {
                eyre::ensure!(last_addr <= vaddr, "unsupported elf structure");
            }
            prev_segment_end_addr =
                Some(vaddr.checked_add(mem_size).ok_or_eyre("last addr overflow")?);

            if (segment.p_flags & PF_X) != 0 {
                if base_address.is_none() {
                    base_address = Some(vaddr);
                    eyre::ensure!(
                        base_address.unwrap() > 0x20,
                        "base address {} should be greater than 0x20",
                        base_address.unwrap()
                    );
                } else {
                    let instr_len: u32 = WORD_SIZE
                        .checked_mul(instructions.len())
                        .ok_or_eyre("instructions length overflow")?
                        .try_into()?;
                    let last_instruction_addr = base_address
                        .unwrap()
                        .checked_add(instr_len)
                        .ok_or_eyre("instruction addr overflow")?;
                    eyre::ensure!(vaddr == last_instruction_addr, "unsupported elf structure");
                }
            }

            // Get the offset to the segment.
            let offset: u32 = segment.p_offset.try_into()?;

            // Read the segment and decode each word as an instruction.
            for i in (0..mem_size).step_by(WORD_SIZE) {
                let addr = vaddr.checked_add(i).ok_or_else(|| eyre::eyre!("vaddr overflow"))?;
                if addr >= BABYBEAR_PRIME {
                    eyre::bail!(
                        "address [0x{addr:08x}] for guest programs must be less than [0x{BABYBEAR_PRIME:08x}]"
                    );
                }

                // If we are reading past the end of the file, then break.
                if i >= file_size {
                    image.insert(addr, 0);
                    continue;
                }

                // Get the word as an u32 but make sure we don't read past the end of the file.
                let mut word = 0;
                let len = min(file_size - i, WORD_SIZE as u32);
                for j in 0..len {
                    let offset = (offset + i + j) as usize;
                    let byte = input
                        .get(offset)
                        .ok_or_else(|| eyre::eyre!("failed to read segment offset"))?;
                    word |= u32::from(*byte) << (j * 8);
                }
                image.insert(addr, word);
                if (segment.p_flags & PF_X) != 0 {
                    instructions.push(word);
                }
            }
        }

        if image.contains_key(&0) {
            eyre::bail!("ELF memory image contains 0");
        }

        if base_address.is_none() {
            eyre::bail!("base address is not found");
        }

        Ok(Elf::new(instructions, entry, base_address.unwrap(), image))
    }
}
