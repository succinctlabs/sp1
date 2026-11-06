use crate::memory::MAX_LOG_ADDR;
use core::ffi::CStr;
use elf::{
    abi::{EM_RISCV, ET_EXEC, PF_R, PF_W, PF_X, PT_LOAD, PT_NOTE},
    endian::LittleEndian,
    file::Class,
    segment::ProgramHeader,
    ElfBytes,
};
use eyre::OptionExt;
use hashbrown::HashMap;
use sp1_primitives::consts::{
    INSTRUCTION_WORD_SIZE, MAXIMUM_MEMORY_SIZE, NOTE_DESC_HEADER, NOTE_DESC_SIZE,
    NOTE_UNTRUSTED_PROGRAM_ENABLED, PAGE_SIZE, PF_UNTRUSTED, STACK_TOP,
};

pub(crate) const TRAP_CONTEXT_SYMBOL: &str = "__SUCCINCT_TRAP_CONTEXT";

/// RISC-V 64IM ELF (Executable and Linkable Format) File.
use std::sync::Arc;
/// RISC-V 32IM ELF (Executable and Linkable Format) File.
///
/// This file represents a binary in the ELF format, specifically the RISC-V 64IM architecture
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
    pub(crate) pc_start: u64,
    /// The base address of the program.
    pub(crate) pc_base: u64,
    /// The trap context address of the program.
    pub(crate) trap_context: Option<u64>,
    /// The initial page protection image, mapping page indices to protection flags.
    pub(crate) page_prot_image: HashMap<u64, u8>,
    /// The initial memory image, useful for global constants.
    pub(crate) memory_image: Arc<HashMap<u64, u64>>,
    /// Function symbols for profiling. In the form of (name, start address, size)
    pub(crate) function_symbols: Vec<(String, u64, u64)>,
    /// The memory region where untrusted program could live in. It is also the
    /// memory region mprotect works on.
    pub(crate) untrusted_memory: Option<(u64, u64)>,
    /// Stacktrace from a dump-elf / bootloader session.
    pub(crate) dump_elf_stack: Vec<u64>,
}

impl Elf {
    /// Create a new [Elf].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        instructions: Vec<u32>,
        pc_start: u64,
        pc_base: u64,
        trap_context: Option<u64>,
        memory_image: HashMap<u64, u64>,
        page_prot_image: HashMap<u64, u8>,
        function_symbols: Vec<(String, u64, u64)>,
        untrusted_memory: Option<(u64, u64)>,
        dump_elf_stack: Vec<u64>,
    ) -> Self {
        Self {
            instructions,
            pc_start,
            pc_base,
            trap_context,
            memory_image: Arc::new(memory_image),
            page_prot_image,
            function_symbols,
            untrusted_memory,
            dump_elf_stack,
        }
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
        let mut image: HashMap<u64, u64> = HashMap::new();
        let mut page_prot_image = HashMap::new();

        // Parse the ELF file assuming that it is little-endian..
        let elf = ElfBytes::<LittleEndian>::minimal_parse(input)?;

        // Some sanity checks to make sure that the ELF file is valid.
        if elf.ehdr.class != Class::ELF32 && elf.ehdr.class != Class::ELF64 {
            eyre::bail!("must be a 32-bit or 64-bit elf");
        } else if elf.ehdr.e_machine != EM_RISCV {
            eyre::bail!("must be a riscv machine");
        } else if elf.ehdr.e_type != ET_EXEC {
            eyre::bail!("must be executable");
        }

        // Get the entrypoint of the ELF file as an u64.
        let entry = elf.ehdr.e_entry;

        // Make sure the entrypoint is valid.
        if entry >= MAXIMUM_MEMORY_SIZE || !entry.is_multiple_of(4) {
            eyre::bail!("invalid entrypoint, entry: {}", entry);
        }

        // Get the segments of the ELF file.
        let segments = elf.segments().ok_or_else(|| eyre::eyre!("failed to get segments"))?;
        if segments.len() > 256 {
            eyre::bail!("too many program headers");
        }

        // Try fetching trap context address
        let trap_context = elf
            .symbol_table()?
            .and_then(|(symbol_table, string_table)| {
                symbol_table.iter().find(|symbol| {
                    if let Ok(name) = string_table.get(symbol.st_name as usize) {
                        name == TRAP_CONTEXT_SYMBOL
                    } else {
                        false
                    }
                })
            })
            .map(|symbol| symbol.st_value);

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = None;

        // Data about the last segment.
        let mut prev_segment_end_addr = None;

        // Untrusted memory region.
        let mut untrusted_memory = None;

        // Check that the segments are sorted and disjoint.
        // Only read segments that are executable instructions that are also PT_LOAD.
        for segment in segments.iter() {
            if segment.p_type == PT_LOAD {
                prev_segment_end_addr = Self::process_load_segment(
                    &segment,
                    input,
                    &mut instructions,
                    &mut base_address,
                    &mut image,
                    &mut page_prot_image,
                    prev_segment_end_addr,
                )?;
            }

            if (segment.p_type == PT_NOTE) && untrusted_memory.is_none() {
                untrusted_memory = Self::process_note_segment(&segment, input)?;
            }
        }

        if base_address.is_none() {
            eyre::bail!("no executable (PF_X) segments found");
        }

        if instructions.is_empty() || instructions.len() > (1 << 22) {
            eyre::bail!("invalid number of instructions");
        }

        #[cfg(not(feature = "profiling"))]
        let function_symbols = Vec::new();

        #[cfg(feature = "profiling")]
        let function_symbols =
            elf.symbol_table()?.map_or_else(Vec::new, |(symbol_table, string_table)| {
                symbol_table
                    .iter()
                    .filter(|sym| sym.st_symtype() == elf::abi::STT_FUNC)
                    .map(|sym| {
                        let name = string_table.get(sym.st_name as usize).unwrap_or("");
                        let demangled_name = rustc_demangle::demangle(name).to_string();
                        let size = sym.st_size;
                        let start_address = sym.st_value;
                        (demangled_name, start_address, size)
                    })
                    .collect()
            });

        #[cfg(not(feature = "profiling"))]
        let dump_elf_stack = Vec::new();

        #[cfg(feature = "profiling")]
        let dump_elf_stack = elf
            .section_headers_with_strtab()
            .ok()
            .and_then(|(section_headers_table, string_table)| {
                match (section_headers_table, string_table) {
                    (Some(section_headers_table), Some(string_table)) => {
                        Some((section_headers_table, string_table))
                    }
                    _ => None,
                }
            })
            .and_then(|(section_headers_table, string_table)| {
                section_headers_table.iter().find(|section_header| {
                    if let Ok(name) = string_table.get(section_header.sh_name as usize) {
                        name == sp1_primitives::consts::PROFILER_STACK_CUSTOM_SECTION_NAME
                    } else {
                        false
                    }
                })
            })
            .and_then(|section| {
                let binary = &input[(section.sh_offset as usize)
                    ..((section.sh_offset + section.sh_size) as usize)];
                bincode::deserialize(binary).ok()
            })
            .unwrap_or_else(Default::default);

        Ok(Elf::new(
            instructions,
            entry,
            base_address.unwrap(),
            trap_context,
            image,
            page_prot_image,
            function_symbols,
            untrusted_memory,
            dump_elf_stack,
        ))
    }

    fn process_load_segment(
        segment: &ProgramHeader,
        input: &[u8],
        instructions: &mut Vec<u32>,
        base_address: &mut Option<u64>,
        image: &mut HashMap<u64, u64>,
        page_prot_image: &mut HashMap<u64, u8>,
        prev_segment_end_addr: Option<u64>,
    ) -> eyre::Result<Option<u64>> {
        // Get the file size and the memory size of the segment.
        let file_size = segment.p_filesz;
        let mem_size = segment.p_memsz;
        if file_size > mem_size {
            eyre::bail!("segment file_size is larger than its mem_size");
        }

        let vaddr = segment.p_vaddr;
        let offset = segment.p_offset;

        let is_execute = (segment.p_flags & PF_X) != 0;
        let is_trusted = is_execute && ((segment.p_flags & PF_UNTRUSTED) == 0);

        if is_trusted && base_address.is_none() {
            *base_address = Some(vaddr);
        }

        // If there are sections below the STACK_TOP, we want to error, this could cause
        // collisions with static values.
        if vaddr < STACK_TOP {
            eyre::bail!("ELF has a segment that is below the STACK_TOP");
        }

        // Only allow segments of the following 3 combinations:
        // * PF_R
        // * PF_R | PF_X
        // * PF_R | PF_W
        if (segment.p_flags & PF_R) == 0 {
            eyre::bail!("ELF has a segment that is not readable");
        }
        if (segment.p_flags & PF_X) != 0 && (segment.p_flags & PF_W) != 0 {
            eyre::bail!("ELF has a segment that is both writable and executable");
        }

        let step_size = INSTRUCTION_WORD_SIZE;

        // Check that the ELF structure is supported.
        if let Some(prev_last_addr) = prev_segment_end_addr {
            eyre::ensure!(prev_last_addr <= vaddr, "unsupported elf structure");
        }

        let end = vaddr
            .checked_add(mem_size)
            .ok_or_else(|| eyre::eyre!("address overflow in segment"))?;

        // The executor memory only covers addresses below `1 << MAX_LOG_ADDR`.
        if end > 1 << MAX_LOG_ADDR {
            eyre::bail!("segment end {end:#x} is outside of the addressable memory");
        }

        // Make sure the virtual address is aligned.
        if !vaddr.is_multiple_of(step_size as u64) {
            eyre::bail!("segment vaddr is not aligned");
        }

        let last_addr = Some(vaddr.checked_add(mem_size).ok_or_eyre("last addr overflow")?);

        if is_trusted {
            if base_address.is_none() {
                *base_address = Some(vaddr);
                eyre::ensure!(
                    base_address.unwrap() > 0x20,
                    "base address {} should be greater than 0x20",
                    base_address.unwrap()
                );
            } else {
                let instr_len: u64 = INSTRUCTION_WORD_SIZE
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

        for addr in (vaddr..end).step_by(step_size) {
            if addr >= vaddr + file_size {
                image.entry(addr - addr % 8).or_insert(0);
                continue;
            }
            let mut word = 0u64;
            let offset_in_file = offset + (addr - vaddr);
            let bytes_to_read = (step_size as u64).min(file_size - (addr - vaddr));
            for i in 0..bytes_to_read {
                let file_idx = (offset_in_file + i) as usize;
                let byte = input
                    .get(file_idx)
                    .ok_or_else(|| eyre::eyre!("failed to read segment offset"))?;
                word |= u64::from(*byte) << (8 * i);
            }
            if addr.is_multiple_of(8) {
                image
                    .entry(addr)
                    .and_modify(|value| {
                        *value += word;
                    })
                    .or_insert_with(|| word);
            } else {
                assert_eq!(addr % 8, 4);
                image
                    .entry(addr - 4)
                    .and_modify(|value| {
                        *value += word << 32;
                    })
                    .or_insert_with(|| word << 32);
            }
            if is_trusted {
                instructions.push(word as u32);
            }
        }

        // Fill in the segment's page prot image.
        let page_start_addr = vaddr - vaddr % PAGE_SIZE as u64;

        for page_start_addr in (page_start_addr..end).step_by(PAGE_SIZE) {
            let page_idx = page_start_addr / PAGE_SIZE as u64;
            page_prot_image.insert(page_idx, segment.p_flags as u8);
        }

        Ok(last_addr)
    }

    fn process_note_segment(
        segment: &ProgramHeader,
        input: &[u8],
    ) -> eyre::Result<Option<(u64, u64)>> {
        let note_segment_offset: usize = segment.p_offset.try_into()?;
        let note_segment_size: usize = segment.p_filesz.try_into()?;
        let note_segment = note_segment_offset
            .checked_add(note_segment_size)
            .and_then(|end| input.get(note_segment_offset..end))
            .ok_or_eyre("note segment is out of bounds")?;
        let mut note_offset: usize = 0;

        let padding = |size| (4 - size % 4) % 4;
        let read = |offset: usize, len: usize| {
            offset
                .checked_add(len)
                .and_then(|end| note_segment.get(offset..end))
                .ok_or_eyre("note entry is out of bounds")
        };
        let read_u32 = |offset: usize| -> eyre::Result<u32> {
            Ok(u32::from_le_bytes(read(offset, 4)?.try_into()?))
        };

        while note_offset < note_segment_size {
            let name_size: usize = read_u32(note_offset)?.try_into()?;
            note_offset += 4;

            let desc_size: usize = read_u32(note_offset)?.try_into()?;
            note_offset += 4;

            let note_type: u32 = read_u32(note_offset)?;
            note_offset += 4;

            let name = {
                let name_slice = read(note_offset, name_size)?;
                // An older version of SP1 puts "SUCCINCT" directly as the name without null terminator.
                // We are preserving this convention not to break older files.
                if name_slice.contains(&0) {
                    CStr::from_bytes_until_nul(name_slice)?.to_str()?
                } else {
                    std::str::from_utf8(name_slice)?
                }
            };
            // Need to increment offset by the padded size of the name.
            note_offset += name_size + padding(name_size);

            let desc_bytes = read(note_offset, desc_size)?;
            note_offset += desc_size + padding(desc_size);

            if name == "SUCCINCT"
                && note_type == NOTE_UNTRUSTED_PROGRAM_ENABLED
                && desc_bytes.len() == NOTE_DESC_SIZE
                && desc_bytes[0..4] == NOTE_DESC_HEADER
            {
                let heap_start = u64::from_le_bytes(desc_bytes[4..12].try_into().unwrap());
                let heap_end = u64::from_le_bytes(desc_bytes[12..20].try_into().unwrap());
                eyre::ensure!(heap_end > heap_start, "invalid untrusted memory range");
                return Ok(Some((heap_start, heap_end)));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_file_bytes_when_zero_fill_shares_word() {
        let file_bytes = [1, 2, 3, 4];
        let segment = ProgramHeader {
            p_type: PT_LOAD,
            p_offset: 0,
            p_vaddr: STACK_TOP,
            p_paddr: STACK_TOP,
            p_filesz: file_bytes.len() as u64,
            p_memsz: 8,
            p_flags: PF_R | PF_W,
            p_align: 4,
        };
        let mut instructions = Vec::new();
        let mut base_address = None;
        let mut image = HashMap::new();
        let mut page_prot_image = HashMap::new();

        Elf::process_load_segment(
            &segment,
            &file_bytes,
            &mut instructions,
            &mut base_address,
            &mut image,
            &mut page_prot_image,
            None,
        )
        .unwrap();

        assert_eq!(image[&STACK_TOP], u64::from_le_bytes([1, 2, 3, 4, 0, 0, 0, 0]));
    }

    const TEXT_VADDR: u64 = STACK_TOP + 0x1000;
    const EHDR_SIZE: u64 = 64;
    const PHDR_SIZE: u64 = 56;

    fn phdr(
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        filesz: u64,
        memsz: u64,
    ) -> ProgramHeader {
        ProgramHeader {
            p_type,
            p_offset,
            p_vaddr,
            p_paddr: p_vaddr,
            p_filesz: filesz,
            p_memsz: memsz,
            p_flags,
            p_align: 4,
        }
    }

    /// Builds a little-endian ELF64 RISC-V executable. `data` is placed right after the
    /// program header table, at offset `data_offset(phdrs.len())`.
    fn build_elf(phdrs: &[ProgramHeader], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        out.extend_from_slice(&EM_RISCV.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&TEXT_VADDR.to_le_bytes()); // e_entry
        out.extend_from_slice(&EHDR_SIZE.to_le_bytes()); // e_phoff
        out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        out.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(phdrs.len() as u16).to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        for p in phdrs {
            out.extend_from_slice(&p.p_type.to_le_bytes());
            out.extend_from_slice(&p.p_flags.to_le_bytes());
            out.extend_from_slice(&p.p_offset.to_le_bytes());
            out.extend_from_slice(&p.p_vaddr.to_le_bytes());
            out.extend_from_slice(&p.p_paddr.to_le_bytes());
            out.extend_from_slice(&p.p_filesz.to_le_bytes());
            out.extend_from_slice(&p.p_memsz.to_le_bytes());
            out.extend_from_slice(&p.p_align.to_le_bytes());
        }
        out.extend_from_slice(data);
        out
    }

    fn data_offset(num_phdrs: usize) -> u64 {
        EHDR_SIZE + PHDR_SIZE * num_phdrs as u64
    }

    /// A text segment holding a single `addi x0, x0, 0`, followed by `extra` headers.
    fn elf_with(extra: &[ProgramHeader], extra_data: &[u8]) -> Vec<u8> {
        let n = 1 + extra.len();
        let mut phdrs = vec![phdr(PT_LOAD, PF_R | PF_X, data_offset(n), TEXT_VADDR, 4, 4)];
        phdrs.extend_from_slice(extra);
        let mut data = 0x0000_0013u32.to_le_bytes().to_vec();
        data.extend_from_slice(extra_data);
        build_elf(&phdrs, &data)
    }

    fn decode_no_panic(bytes: &[u8]) -> std::thread::Result<eyre::Result<Elf>> {
        std::panic::catch_unwind(|| Elf::decode(bytes))
    }

    #[test]
    fn minimal_elf_decodes() {
        let elf = Elf::decode(&elf_with(&[], &[])).unwrap();
        assert_eq!(elf.instructions, vec![0x0000_0013]);
    }

    #[test]
    fn note_segment_offset_past_end_of_file() {
        let bytes = elf_with(&[phdr(PT_NOTE, PF_R, 0x10_0000, 0, 24, 24)], &[]);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }

    #[test]
    fn note_segment_truncated_header() {
        // 6 bytes is not enough for the 12 byte note header.
        let off = data_offset(2) + 4;
        let bytes = elf_with(&[phdr(PT_NOTE, PF_R, off, 0, 6, 6)], &[0u8; 6]);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }

    #[test]
    fn note_segment_name_size_past_segment() {
        let off = data_offset(2) + 4;
        let mut note = Vec::new();
        note.extend_from_slice(&0xffffu32.to_le_bytes()); // namesz
        note.extend_from_slice(&0u32.to_le_bytes()); // descsz
        note.extend_from_slice(&0u32.to_le_bytes()); // type
        let bytes = elf_with(&[phdr(PT_NOTE, PF_R, off, 0, note.len() as u64, 0)], &note);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }

    #[test]
    fn note_segment_inverted_heap_range() {
        let off = data_offset(2) + 4;
        let mut note = Vec::new();
        note.extend_from_slice(&9u32.to_le_bytes()); // namesz ("SUCCINCT\0")
        note.extend_from_slice(&(NOTE_DESC_SIZE as u32).to_le_bytes());
        note.extend_from_slice(&NOTE_UNTRUSTED_PROGRAM_ENABLED.to_le_bytes());
        note.extend_from_slice(b"SUCCINCT\0\0\0\0");
        note.extend_from_slice(&NOTE_DESC_HEADER);
        note.extend_from_slice(&0x2000_0000u64.to_le_bytes()); // heap_start
        note.extend_from_slice(&0x1000_0000u64.to_le_bytes()); // heap_end < heap_start
        let bytes = elf_with(&[phdr(PT_NOTE, PF_R, off, 0, note.len() as u64, 0)], &note);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }

    #[test]
    fn load_segment_past_max_address_rejected() {
        // A data segment whose end lies beyond the 48-bit address space.
        let vaddr = 1u64 << 48;
        let bytes = elf_with(&[phdr(PT_LOAD, PF_R | PF_W, 0, vaddr, 0, 8)], &[]);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }

    #[test]
    fn load_segment_filesz_larger_than_memsz_rejected() {
        let bytes = elf_with(&[phdr(PT_LOAD, PF_R | PF_W, 0, TEXT_VADDR + 0x1000, 64, 8)], &[]);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }

    #[test]
    fn huge_bss_past_address_space_rejected() {
        // A 2^47 byte .bss used to be zero-filled word by word (~2^45 hash map inserts).
        let bytes =
            elf_with(&[phdr(PT_LOAD, PF_R | PF_W, 0, TEXT_VADDR + 0x1000, 0, 1u64 << 47)], &[]);
        let res = decode_no_panic(&bytes);
        assert!(matches!(res, Ok(Err(_))), "expected an error, got {:?}", res.map(|r| r.is_ok()));
    }
}
