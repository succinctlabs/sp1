use std::cmp::min;
use std::collections::BTreeMap;

use elf::abi::{EM_RISCV, ET_EXEC, PF_X, PT_LOAD};
use elf::endian::LittleEndian;
use elf::file::Class;
use elf::ElfBytes;

/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// A RV32IM ELF file.
#[derive(Debug, Clone)]
pub struct Elf {
    /// The instructions of the program encoded as 32-bits.
    pub instructions: Vec<u32>,

    /// The start address of the program.
    pub pc_start: u32,

    /// The base address of the program.
    pub pc_base: u32,

    /// The initial memory image, useful for global constants.
    pub memory_image: BTreeMap<u32, u32>,
}

impl Elf {
    /// Create a new ELF file.
    pub const fn new(
        instructions: Vec<u32>,
        pc_start: u32,
        pc_base: u32,
        memory_image: BTreeMap<u32, u32>,
    ) -> Self {
        Self {
            instructions,
            pc_start,
            pc_base,
            memory_image,
        }
    }

    /// Parse the ELF file into a vector of 32-bit encoded instructions and the first memory address.
    ///
    /// Reference: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    pub fn decode(input: &[u8]) -> Self {
        let mut image: BTreeMap<u32, u32> = BTreeMap::new();
        // Parse the ELF file assuming that it is little-endian..
        let elf = ElfBytes::<LittleEndian>::minimal_parse(input).expect("failed to parse elf");

        // Some sanity checks to make sure that the ELF file is valid.
        if elf.ehdr.class != Class::ELF32 {
            panic!("must be a 32-bit elf");
        } else if elf.ehdr.e_machine != EM_RISCV {
            panic!("must be a riscv machine");
        } else if elf.ehdr.e_type != ET_EXEC {
            panic!("must be executable");
        }

        // Get the entrypoint of the ELF file as an u32.
        let entry: u32 = elf
            .ehdr
            .e_entry
            .try_into()
            .expect("e_entry was larger than 32 bits");

        // Make sure the entrypoint is valid.
        if entry == MAXIMUM_MEMORY_SIZE || entry % WORD_SIZE as u32 != 0 {
            panic!("invalid entrypoint");
        }

        // Get the segments of the ELF file.
        let segments = elf.segments().expect("failed to get segments");
        if segments.len() > 256 {
            panic!("too many program headers");
        }

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = u32::MAX;

        // Only read segments that are executable instructions that are also PT_LOAD.
        for segment in segments.iter().filter(|x| x.p_type == PT_LOAD) {
            // Get the file size of the segment as an u32.
            let file_size: u32 = segment
                .p_filesz
                .try_into()
                .expect("filesize was larger than 32 bits");
            if file_size == MAXIMUM_MEMORY_SIZE {
                panic!("invalid segment file_size");
            }

            // Get the memory size of the segment as an u32.
            let mem_size: u32 = segment
                .p_memsz
                .try_into()
                .expect("mem_size was larger than 32 bits");
            if mem_size == MAXIMUM_MEMORY_SIZE {
                panic!("Invalid segment mem_size");
            }

            // Get the virtual address of the segment as an u32.
            let vaddr: u32 = segment
                .p_vaddr
                .try_into()
                .expect("vaddr was larger than 32 bits");
            if vaddr % WORD_SIZE as u32 != 0 {
                panic!("vaddr {vaddr:08x} is unaligned");
            }

            // If the virtual address is less than the first memory address, then update the first
            // memory address.
            if (segment.p_flags & PF_X) != 0 && base_address > vaddr {
                base_address = vaddr;
            }

            // Get the offset to the segment.
            let offset: u32 = segment
                .p_offset
                .try_into()
                .expect("offset was larger than 32 bits");

            // Read the segment and decode each word as an instruction.
            for i in (0..mem_size).step_by(WORD_SIZE) {
                let addr = vaddr.checked_add(i).expect("invalid segment vaddr");
                if addr == MAXIMUM_MEMORY_SIZE {
                    panic!("address [0x{addr:08x}] exceeds maximum address for guest programs [0x{MAXIMUM_MEMORY_SIZE:08x}]");
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
                    let byte = input.get(offset).expect("invalid segment offset");
                    word |= (*byte as u32) << (j * 8);
                }
                image.insert(addr, word);
                if (segment.p_flags & PF_X) != 0 {
                    instructions.push(word);
                }
            }
        }

        Elf::new(instructions, entry, base_address, image)
    }
}
