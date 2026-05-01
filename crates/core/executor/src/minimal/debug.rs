#![allow(clippy::too_many_lines)]

use hashbrown::HashMap;
use object::{
    elf,
    endian::Endianness,
    write::elf::{FileHeader, ProgramHeader, SectionHeader, Sym, Writer as ElfWriter},
};
use sp1_jit::{ElfInfo, RiscRegister, SyscallContext};
use sp1_primitives::consts::{
    DEFAULT_PAGE_PROT, LOG_PAGE_SIZE, MAXIMUM_DUMPED_PERMISSIONS, MAXIMUM_ELF_SEGMENTS, PAGE_SIZE,
    PERMISSION_BUFFER_SIZE, PF_UNTRUSTED, PROT_EXEC, PROT_READ,
};
use std::collections::BTreeMap;
use std::str::FromStr;

pub fn insert_profile_symbols_syscall(
    ctx: &mut impl SyscallContext,
    addr: u64,
    len: u64,
) -> Option<u64> {
    let aligned_start = addr & !0b111;
    let align_offset = addr - aligned_start;
    let aligned_len = (len + align_offset).div_ceil(8);

    let data: Vec<u8> = ctx
        .mr_slice_no_trace(aligned_start, aligned_len as usize)
        .into_iter()
        .flat_map(|double_word| double_word.to_le_bytes())
        .collect();
    let s = core::str::from_utf8(&data[align_offset as usize..(align_offset + len) as usize])
        .expect("build utf8 string from bytes");

    let profiler_data: HashMap<String, (String, String)> =
        serde_json::from_str(s).expect("parse profiler data");
    let profiler_data: HashMap<u64, (String, u64)> = profiler_data
        .into_iter()
        .map(|(index, (name, len))| {
            (u64::from_str(&index).unwrap(), (name, u64::from_str(&len).unwrap()))
        })
        .collect();

    ctx.maybe_insert_profiler_symbols(
        profiler_data.into_iter().map(|(addr, (name, len))| (name, addr, len)),
    );

    None
}

pub fn delete_profile_symbols_syscall(
    ctx: &mut impl SyscallContext,
    addr: u64,
    len: u64,
) -> Option<u64> {
    let aligned_start = addr & !0b111;
    let align_offset = addr - aligned_start;
    let aligned_len = (len + align_offset).div_ceil(8);

    let data: Vec<u8> = ctx
        .mr_slice_no_trace(aligned_start, aligned_len as usize)
        .into_iter()
        .flat_map(|double_word| double_word.to_le_bytes())
        .collect();
    let s = core::str::from_utf8(&data[align_offset as usize..(align_offset + len) as usize])
        .expect("build utf8 string from bytes");

    let addresses: Vec<String> = serde_json::from_str(s).expect("parse addrs");
    let addresses: Vec<u64> =
        addresses.into_iter().map(|addr| u64::from_str(&addr).unwrap()).collect();

    ctx.maybe_delete_profiler_symbols(addresses.into_iter());

    None
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
struct Segment {
    start_page: u64,
    pages: u64,
    t: SegmentType,
    padding_before: u64,
    padding_after: u64,
}

impl Segment {
    fn contains(&self, page: u64) -> bool {
        (self.start_page..self.start_page + self.pages).contains(&page)
    }

    fn single_page(page: u64, t: SegmentType) -> Self {
        Self { start_page: page, pages: 1, t, padding_before: 0, padding_after: 0 }
    }

    fn start_address(&self) -> u64 {
        (self.start_page << LOG_PAGE_SIZE) + self.padding_before
    }

    fn end_address(&self) -> u64 {
        ((self.start_page + self.pages) << LOG_PAGE_SIZE) - self.padding_after
    }

    fn real_size(&self) -> u64 {
        self.end_address() - self.start_address()
    }

    fn from_double_word(address: u64, t: SegmentType) -> Self {
        assert_eq!(address % 8, 0);
        let end_address = address + 8;

        let page = address >> LOG_PAGE_SIZE;
        let page_start_address = page << LOG_PAGE_SIZE;
        let page_end_address = page_start_address + PAGE_SIZE as u64;
        assert!(end_address <= page_end_address);

        Self {
            start_page: page,
            pages: 1,
            t,
            padding_before: address - page_start_address,
            padding_after: page_end_address - end_address,
        }
    }

    fn extend_double_word(&mut self, address: u64) {
        assert_eq!(address % 8, 0);
        self.extend(address, address + 8);
    }

    // Extend non-padding region within a single page
    fn extend(&mut self, start_address: u64, end_address: u64) {
        assert_eq!(self.pages, 1);

        let page_start_address = self.start_page << LOG_PAGE_SIZE;
        let page_end_address = page_start_address + PAGE_SIZE as u64;
        assert!(start_address >= page_start_address);
        assert!(end_address <= page_end_address);

        self.padding_before =
            std::cmp::min(self.padding_before, start_address - page_start_address);
        self.padding_after = std::cmp::min(self.padding_after, page_end_address - end_address);
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
enum SegmentType {
    Code,
    Data,
    Note,
    UntrustedCode,
    Custom(u32),
}

impl SegmentType {
    fn is_code(self) -> bool {
        matches!(self, SegmentType::Code | SegmentType::UntrustedCode)
    }

    fn sp1_permission(self) -> u8 {
        match self {
            SegmentType::Code | SegmentType::UntrustedCode => PROT_READ | PROT_EXEC,
            SegmentType::Data => DEFAULT_PAGE_PROT,
            SegmentType::Note => 0,
            SegmentType::Custom(prot) => prot as u8,
        }
    }
}

pub fn dump_elf_syscall(
    ctx: &mut impl SyscallContext,
    saved_sp_addr: u64,
    buffer_addr: u64,
) -> Option<u64> {
    let Ok(save_path) = std::env::var("DUMP_ELF_OUTPUT") else {
        return None;
    };

    let merge_pages = |mut pages: Vec<Segment>| {
        pages.sort_by_key(|s| s.start_page);
        pages.dedup_by_key(|s| s.start_page);

        let mut merged: Vec<Segment> = Vec::new();

        for s in pages {
            let mut processed = false;
            if let Some(last) = merged.last_mut() {
                if last.start_page + last.pages == s.start_page && last.t == s.t {
                    last.pages += s.pages;
                    last.padding_after = s.padding_after;
                    processed = true;
                }
            }
            if !processed {
                merged.push(s);
            }
        }
        merged
    };

    // a2
    let elf_entrypoint = ctx.rr(RiscRegister::X12);
    // a3. Reserved input region will be fully uninitialized after bootloading process.
    // This helps ensure that the bootloaded program will load its own stdin input.
    let reserved_input_start = ctx.rr(RiscRegister::X13);
    // a4. EMBEDDED_RESERVED_INPUT_PTR address, we will need to reset this value
    // in bootloading process.
    let reserved_input_ptr = ctx.rr(RiscRegister::X14);

    // In the newly dumped ELF, certain memory addresses should contain updated values.
    // Such as register values, page permissions. We use this data structure to keep
    // the new values. Later we would update them directly in the ELF, not in current VM.
    let mut new_values = BTreeMap::new();
    // Save GRP registers in memory
    // sp
    new_values.insert(saved_sp_addr, ctx.rr(RiscRegister::X2));
    // ra
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64, ctx.rr(RiscRegister::X1));
    // gp
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 8, ctx.rr(RiscRegister::X3));
    // tp
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 16, ctx.rr(RiscRegister::X4));
    // t0
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 24, ctx.rr(RiscRegister::X5));
    // t1
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 32, ctx.rr(RiscRegister::X6));
    // t2
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 40, ctx.rr(RiscRegister::X7));
    // s0
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 48, ctx.rr(RiscRegister::X8));
    // s1
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 56, ctx.rr(RiscRegister::X9));
    // a0
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 64, ctx.rr(RiscRegister::X10));
    // a1
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 72, ctx.rr(RiscRegister::X11));
    // a2
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 80, ctx.rr(RiscRegister::X12));
    // a3
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 88, ctx.rr(RiscRegister::X13));
    // a4
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 96, ctx.rr(RiscRegister::X14));
    // a5
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 104, ctx.rr(RiscRegister::X15));
    // a6
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 112, ctx.rr(RiscRegister::X16));
    // a7
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 120, ctx.rr(RiscRegister::X17));
    // s2
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 128, ctx.rr(RiscRegister::X18));
    // s3
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 136, ctx.rr(RiscRegister::X19));
    // s4
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 144, ctx.rr(RiscRegister::X20));
    // s5
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 152, ctx.rr(RiscRegister::X21));
    // s6
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 160, ctx.rr(RiscRegister::X22));
    // s7
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 168, ctx.rr(RiscRegister::X23));
    // s8
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 176, ctx.rr(RiscRegister::X24));
    // s9
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 184, ctx.rr(RiscRegister::X25));
    // s10
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 192, ctx.rr(RiscRegister::X26));
    // s11
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 200, ctx.rr(RiscRegister::X27));
    // t3
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 208, ctx.rr(RiscRegister::X28));
    // t3
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 216, ctx.rr(RiscRegister::X29));
    // t3
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 224, ctx.rr(RiscRegister::X30));
    // t3
    new_values.insert(buffer_addr + PERMISSION_BUFFER_SIZE as u64 + 232, ctx.rr(RiscRegister::X31));
    // Reserved input ptr will be updated
    new_values.insert(reserved_input_ptr, reserved_input_start);

    // Only text section from the original ELF program becomes trusted code.
    // All executable memories marked as executable via mprotect stays as untrusted
    // code after dumping.
    let (elf_segment, untrusted_memory_range) = {
        let ElfInfo { pc_base: elf_start, instruction_count, untrusted_memory } = ctx.elf_info();
        let elf_start_page = elf_start / PAGE_SIZE as u64;
        let elf_end = elf_start + instruction_count as u64 * 4;
        let elf_end_page = elf_end.div_ceil(PAGE_SIZE as u64);
        let elf_pages = elf_end_page - elf_start_page;
        let (heap_start, heap_end) = untrusted_memory.unwrap_or_default();
        (
            Segment {
                start_page: elf_start_page,
                pages: elf_pages,
                t: SegmentType::Code,
                padding_before: elf_start - (elf_start_page << LOG_PAGE_SIZE),
                padding_after: (elf_end_page << LOG_PAGE_SIZE) - elf_end,
            },
            heap_start..heap_end,
        )
    };

    let mut segments = vec![elf_segment];
    // Find all pages that:
    // 1. Executable via mprotect, mark those as untrusted code segments.
    // 2. Fall in trusted memory, but do not use default page permission. One
    //    example is readonly memory.
    let custom_permissions: HashMap<u64, SegmentType> = ctx
        .page_prot_iter()
        .into_iter()
        .filter_map(|(p, prot)| {
            if !elf_segment.contains(*p) {
                if prot.value & PROT_EXEC != 0 {
                    return Some((*p, SegmentType::UntrustedCode));
                }
                if (prot.value != DEFAULT_PAGE_PROT)
                    && (!untrusted_memory_range.contains(&(p << LOG_PAGE_SIZE)))
                {
                    return Some((*p, SegmentType::Custom(prot.value.into())));
                }
            }
            None
        })
        .collect();

    // Dump all initialized memory data to external ELF file.
    {
        let mut initialized_pages: HashMap<u64, Segment> = HashMap::new();

        let mut mark_address = |addr: u64| {
            initialized_pages
                .entry(addr >> LOG_PAGE_SIZE)
                .and_modify(|segment| segment.extend_double_word(addr))
                // The segment type here is merely a placeholder, we might change them later.
                .or_insert_with(|| Segment::from_double_word(addr, SegmentType::Data));
        };

        // Memory address holding new values(register values, page permissions)
        // are counted as initialized as well.
        for addr in new_values.keys() {
            mark_address(*addr);
        }
        for addr in (buffer_addr..buffer_addr + PERMISSION_BUFFER_SIZE as u64).step_by(8) {
            mark_address(addr);
        }

        for addr in ctx.init_addr_iter() {
            // NOTE: we cannot assume uninitialized memory will be 0,
            // SP1's prover does not enforce this.
            // All data in input region will be ignored. A bootloaded program is expected
            // to read its own stdin input.
            if addr < reserved_input_start {
                mark_address(addr);
            }
        }

        // Segments alone contains all the information
        let initialized_pages: Vec<_> = initialized_pages.into_values().collect();

        // Extract initialized pages with special permissions
        let custom_permission_pages: Vec<Segment> = initialized_pages
            .iter()
            .filter_map(|segment| {
                if let Some(t) = custom_permissions.get(&segment.start_page) {
                    let mut segment = *segment;
                    segment.t = *t;
                    Some(segment)
                } else {
                    None
                }
            })
            .collect();
        // Those pages with custom permissions become segments directly
        segments.extend(merge_pages(custom_permission_pages));
        // Set aside 1 for `.note.succinct`, and another one for initialized memory data
        assert!(segments.len() + 1 < MAXIMUM_ELF_SEGMENTS);

        // Now we care only those pages using default permissions, or data pages.
        let mut data_segments = merge_pages(
            initialized_pages
                .into_iter()
                .filter(|page| segments.iter().all(|segment| !segment.contains(page.start_page)))
                .collect(),
        );

        // If too many segments are generated, try merging some without disrupting permissions
        while segments.len() + 1 + data_segments.len() > MAXIMUM_ELF_SEGMENTS {
            let mut target = None;

            for i in 0..data_segments.len() - 1 {
                let end_page = data_segments[1].start_page + data_segments[1].pages;
                let merged_range = data_segments[0].start_page..end_page;

                if segments.iter().any(|segment| merged_range.contains(&segment.start_page)) {
                    continue;
                }

                let current_gaps = data_segments[1].start_page
                    - (data_segments[0].start_page + data_segments[0].pages);
                let found_target =
                    if let Some((_, gaps)) = target { current_gaps < gaps } else { true };

                if found_target {
                    target = Some((i, current_gaps));
                }
            }

            if let Some((i, gaps)) = target {
                data_segments[i].pages += gaps + data_segments[i + 1].pages;
                data_segments.remove(i + 1);
            } else {
                panic!("Too many ELF segments!");
            }
        }

        // Merge data segments into segments
        segments.extend(data_segments);
    }

    // Trusted memory with special permissions will all become their own segments. We
    // only need to deal with untrusted memory with special permissions here. Those
    // permissions will be kepted in a custom data structure, the bootloader will reset
    // them to correct permissions.
    {
        let mprotect_pages: Vec<_> = ctx
            .page_prot_iter()
            .into_iter()
            .filter_map(|(page, prot)| {
                if (prot.value != DEFAULT_PAGE_PROT)
                    && segments.iter().all(|segment| !segment.contains(*page))
                {
                    Some(Segment::single_page(*page, SegmentType::Custom(prot.value.into())))
                } else {
                    None
                }
            })
            .collect();

        let mut mprotect_segments = merge_pages(mprotect_pages);
        // UntrustedCode requires mprotect to set page permissions as well
        mprotect_segments
            .extend(segments.iter().filter(|segment| segment.t == SegmentType::UntrustedCode));
        assert!(mprotect_segments.len() <= MAXIMUM_DUMPED_PERMISSIONS);

        // Permissions will be written directly to the newly dumped ELF.
        let mut current_addr = buffer_addr;
        for Segment { start_page, pages, t, padding_before, padding_after } in mprotect_segments {
            // mprotect segements shall be all full pages
            assert_eq!(padding_before, 0);
            assert_eq!(padding_after, 0);

            let region_addr = start_page << LOG_PAGE_SIZE;
            let region_length = pages << LOG_PAGE_SIZE;

            new_values.insert(current_addr, region_addr);
            new_values.insert(current_addr + 8, region_length);
            new_values.insert(current_addr + 16, t.sp1_permission() as u64);

            current_addr += 24;
        }
        new_values.insert(current_addr, 0);
    };

    // Dump memory data into segments.
    // (start address, length, type, data). This form fits ELF better.
    let mut segments: Vec<_> = {
        let mut dump_memory = |start_address: u64, end_address: u64| {
            let aligned_start_address = start_address / 8 * 8;
            let aligned_end_address = end_address.div_ceil(8) * 8;

            let count = (aligned_end_address - aligned_start_address) / 8;

            let mut values: Vec<u64> = ctx
                .mr_slice_no_trace(aligned_start_address, count as usize)
                .into_iter()
                .copied()
                .collect();
            // When a new value is present, use it to replace current value
            for (addr, new_value) in new_values.range(aligned_start_address..aligned_end_address) {
                assert!(addr % 8 == 0);
                let index = (addr - aligned_start_address) / 8;
                values[index as usize] = *new_value;
            }

            let mut bytes: Vec<u8> = values.into_iter().flat_map(u64::to_le_bytes).collect();
            bytes.drain(0..(start_address - aligned_start_address) as usize);
            bytes.drain((end_address - start_address) as usize..);
            bytes
        };

        segments
            .into_iter()
            .map(|segment| {
                let data: Vec<u8> = dump_memory(segment.start_address(), segment.end_address());

                (segment.start_address(), segment.real_size(), segment.t, data)
            })
            .collect()
    };

    // Sort the segments so they use an increasing order of vaddr.
    segments.sort_by_key(|(start_page, _, _, _)| *start_page);

    if let ElfInfo { untrusted_memory: Some((heap_start, heap_end)), .. } = ctx.elf_info() {
        let succinct_note = {
            use sp1_primitives::consts::{
                NOTE_DESC_HEADER, NOTE_DESC_PADDING_SIZE, NOTE_DESC_SIZE, NOTE_NAME,
                NOTE_NAME_PADDING_SIZE, NOTE_UNTRUSTED_PROGRAM_ENABLED,
            };

            let mut note = vec![];
            note.extend_from_slice(&(NOTE_NAME.len() as u32).to_le_bytes());
            note.extend_from_slice(&(NOTE_DESC_SIZE as u32).to_le_bytes());
            note.extend_from_slice(&NOTE_UNTRUSTED_PROGRAM_ENABLED.to_le_bytes());

            note.extend_from_slice(&NOTE_NAME);
            note.extend_from_slice(&[0u8; NOTE_NAME_PADDING_SIZE]);

            note.extend_from_slice(&NOTE_DESC_HEADER);
            note.extend_from_slice(&heap_start.to_le_bytes());
            note.extend_from_slice(&heap_end.to_le_bytes());
            note.extend_from_slice(&[0u8; NOTE_DESC_PADDING_SIZE]);

            note
        };
        segments.push((0, succinct_note.len() as u64, SegmentType::Note, succinct_note));
    }

    #[allow(unused_mut)]
    let mut custom_sections = vec![];

    // When profiling mode is used, we can:
    // * Gather function names for debugging usage.
    // * Serialize profiler current stack to the ELF binary, so we can
    // recover the same stack next time we profile the dumped binary.
    #[allow(unused_mut)]
    let mut funcs = vec![];
    #[cfg(feature = "profiling")]
    {
        let (mut loaded_functions, stack) = ctx.maybe_dump_profiler_data();
        std::mem::swap(&mut funcs, &mut loaded_functions);

        let stack_binary = bincode::serialize(&stack).expect("encode stack via bincode");
        custom_sections.push((
            sp1_primitives::consts::PROFILER_STACK_CUSTOM_SECTION_NAME.to_string(),
            stack_binary,
        ));
    }

    let elf_data = dump_to_elf(elf_entrypoint, &segments, &funcs, &custom_sections)
        .expect("dump memory state to ELF file!");

    tracing::info!("Dump ELF file to {}", save_path);
    std::fs::write(save_path, elf_data).expect("write");

    None
}

fn dump_to_elf(
    entrypoint: u64,
    segments: &[(u64, u64, SegmentType, Vec<u8>)],
    funcs: &[(String, u64, u64)],
    custom_sections: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out_data = Vec::new();
    let mut writer = ElfWriter::new(Endianness::Little, true, &mut out_data);

    writer.reserve_strtab_section_index();
    writer.reserve_shstrtab_section_index();
    writer.reserve_symtab_section_index();

    // We need those names in stack since +add_section_name+ has a specific
    // lifetime requirement.
    let text_section_names: Vec<_> = segments
        .iter()
        .filter(|(_, _, t, _)| t.is_code())
        .enumerate()
        .map(|(i, _)| if i == 0 { ".text".to_string() } else { format!(".text{i}") })
        .collect();
    let text_section_infos: Vec<_> = segments
        .iter()
        .filter(|(_, _, t, _)| t.is_code())
        .enumerate()
        .map(|(i, (address, length, _, _))| {
            (
                writer.add_section_name(text_section_names[i].as_bytes()),
                writer.reserve_section_index(),
                *address,
                *length,
            )
        })
        .collect();

    let mut symbols = vec![];
    for (name, address, length) in funcs {
        let sym_index = writer.reserve_symbol_index(None);
        let str_index = writer.add_string(name.as_bytes());

        symbols.push((address, length, sym_index, str_index));
    }

    writer.reserve_file_header();
    writer.reserve_program_headers(segments.len() as u32);

    let actual_data_start_offset = writer.reserved_len() as u64;
    // Reserve space for actual program data
    let mut data_lengths = vec![];
    let mut merged_data = vec![];
    for (_, _, _, data) in segments {
        data_lengths.push(data.len() as u64);
        merged_data.extend(data);
    }
    writer.reserve(merged_data.len(), 1);

    // Reserve space for custom section data
    let mut custom_section_infos = vec![];
    {
        let mut offset = writer.reserved_len();
        let mut total_length = 0;
        for (name, data) in custom_sections {
            let len = data.len();
            let name_id = writer.add_section_name(name.as_bytes());
            let section_index = writer.reserve_section_index();
            custom_section_infos.push((name_id, section_index, offset, len));
            offset += len;
            total_length += len;
        }
        writer.reserve(total_length, 1);
    }

    writer.reserve_symtab();
    writer.reserve_strtab();
    writer.reserve_shstrtab();
    writer.reserve_section_headers();

    writer.write_file_header(&FileHeader {
        os_abi: 0,
        abi_version: 0,
        // Executable ELF type
        e_type: elf::ET_EXEC,
        // RISC-V machine
        e_machine: elf::EM_RISCV,
        e_flags: 0,
        e_entry: entrypoint,
    })?;

    // Unlike traditional ELFs where sections map to data, here we have
    // program headers map to data.
    let mut text_section_offsets = Vec::with_capacity(text_section_infos.len());
    {
        let mut offset = actual_data_start_offset;
        for (i, (address, length, t, _)) in segments.iter().enumerate() {
            let (elf_type, flags, align) = match t {
                SegmentType::Code => (elf::PT_LOAD, elf::PF_X | elf::PF_R, PAGE_SIZE),
                SegmentType::UntrustedCode => {
                    (elf::PT_LOAD, elf::PF_X | elf::PF_R | PF_UNTRUSTED, PAGE_SIZE)
                }
                SegmentType::Data => (elf::PT_LOAD, elf::PF_W | elf::PF_R, PAGE_SIZE),
                SegmentType::Note => (elf::PT_NOTE, elf::PF_R, 0x1),
                SegmentType::Custom(prot) => (elf::PT_LOAD, *prot, PAGE_SIZE),
            };
            if t.is_code() {
                text_section_offsets.push(offset);
            }

            writer.write_program_header(&ProgramHeader {
                p_type: elf_type,
                p_flags: flags,
                p_offset: offset,
                p_vaddr: *address,
                p_paddr: *address,
                p_filesz: data_lengths[i],
                p_memsz: *length,
                p_align: align as u64,
            });
            offset += data_lengths[i];
        }
        writer.write(&merged_data);
    }
    assert_eq!(text_section_offsets.len(), text_section_infos.len());

    // Write custom section data
    for (_, data) in custom_sections {
        writer.write(data);
    }

    // symtab
    writer.write_null_symbol();
    for (address, length, _sym_index, str_index) in symbols {
        let text_section_index = text_section_infos
            .iter()
            .find(|(_, _, section_address, section_length)| {
                address >= section_address && *address < section_address + section_length
            })
            .map_or(elf::SHN_UNDEF, |(_, section_index, _, _)| section_index.0 as u16);

        writer.write_symbol(&Sym {
            name: Some(str_index),
            section: None,
            st_info: (elf::STB_GLOBAL << 4) | elf::STT_FUNC,
            st_other: elf::STV_DEFAULT,
            st_shndx: text_section_index,
            st_value: *address,
            st_size: *length,
        });
    }
    writer.write_strtab();
    writer.write_shstrtab();

    // section headers
    writer.write_null_section_header();
    writer.write_strtab_section_header();
    writer.write_shstrtab_section_header();
    writer.write_symtab_section_header(writer.symbol_count());
    // text sections
    for ((name, _, address, length), offset) in
        text_section_infos.iter().zip(text_section_offsets.iter())
    {
        writer.write_section_header(&SectionHeader {
            name: Some(*name),
            sh_type: elf::SHT_PROGBITS,
            sh_flags: (elf::SHF_ALLOC | elf::SHF_EXECINSTR).into(),
            sh_addr: *address,
            sh_offset: *offset,
            sh_size: *length,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 4,
            sh_entsize: 0,
        });
    }
    // custom sections
    for (name, _, data_offset, data_length) in custom_section_infos {
        writer.write_section_header(&SectionHeader {
            name: Some(name),
            sh_type: elf::SHT_NULL,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: data_offset as u64,
            sh_size: data_length as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
    }

    Ok(out_data)
}
