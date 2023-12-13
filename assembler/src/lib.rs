use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;


use curta_core::runtime::{Instruction, create_instruction};
use elf::ElfBytes;

use elf::endian::LittleEndian;
use elf::file::Class;

pub fn parse_elf(input: &[u8]) -> Result<Vec<Instruction>> {
    let elf = ElfBytes::<LittleEndian>::minimal_parse(input)
        .map_err(|err| anyhow!("Elf parse error: {err}"))?;
    if elf.ehdr.class != Class::ELF32 {
        bail!("Not a 32-bit ELF");
    }
    if elf.ehdr.e_machine != elf::abi::EM_RISCV {
        bail!("Invalid machine type, must be RISC-V");
    }
    if elf.ehdr.e_type != elf::abi::ET_EXEC {
        bail!("Invalid ELF type, must be executable");
    }
    let entry: u32 = elf
        .ehdr
        .e_entry
        .try_into()
        .map_err(|err| anyhow!("e_entry was larger than 32 bits. {err}"))?;

    let max_mem = 1000000; // TODO: figure out what this is.
    let word_size = 4;

    if entry >= max_mem || entry % word_size as u32 != 0 {
        bail!("Invalid entrypoint");
    }
    let segments = elf.segments().ok_or(anyhow!("Missing segment table"))?;
    if segments.len() > 256 {
        bail!("Too many program headers");
    }
    let mut instructions : Vec<Instruction> = Vec::new();

    // Only read segments that are executable instructions that are also PT_LOAD.
    for segment in segments.iter().filter(|x| x.p_type == elf::abi::PT_LOAD && ((x.p_flags & elf::abi::PF_X) != 0)) {
        let file_size: u32 = segment
            .p_filesz
            .try_into()
            .map_err(|err| anyhow!("filesize was larger than 32 bits. {err}"))?;
        if file_size >= max_mem {
            bail!("Invalid segment file_size");
        }
        let mem_size: u32 = segment
            .p_memsz
            .try_into()
            .map_err(|err| anyhow!("mem_size was larger than 32 bits {err}"))?;
        if mem_size >= max_mem {
            bail!("Invalid segment mem_size");
        }
        let vaddr: u32 = segment
            .p_vaddr
            .try_into()
            .map_err(|err| anyhow!("vaddr is larger than 32 bits. {err}"))?;
        if vaddr % word_size as u32 != 0 {
            bail!("vaddr {vaddr:08x} is unaligned");
        }
        let offset: u32 = segment
            .p_offset
            .try_into()
            .map_err(|err| anyhow!("offset is larger than 32 bits. {err}"))?;
        for i in (0..mem_size).step_by(word_size) {
            let addr = vaddr.checked_add(i).context("Invalid segment vaddr")?;
            if addr >= max_mem {
                bail!("Address [0x{addr:08x}] exceeds maximum address for guest programs [0x{max_mem:08x}]");
            }
            if i >= file_size {
                // Past the file size, all zeros.
                // TODO: I think this is no-op, but double check that.
                // image.insert(addr, 0);
            } else {
                let mut word = 0;
                // Don't read past the end of the file.
                let len = core::cmp::min(file_size - i, word_size as u32);
                for j in 0..len {
                    let offset = (offset + i + j) as usize;
                    let byte = input.get(offset).context("Invalid segment offset")?;
                    word |= (*byte as u32) << (j * 8);
                }
                println!("address => [0x{addr:08x}], word => {}", word);
                instructions.push(create_instruction(word));
            }
        }
    }
    Ok(instructions)
}