//! Serializable, persistent representation of JIT-compiled x86-64 code.
//!
//! [`CompiledCode`] lets you:
//! * **Cache** a JIT compilation result to disk and reload it later with
//!   [`CompiledCode::save`] / [`CompiledCode::load`].
//! * **Reconstruct** a [`crate::JitFunction`] from a cached blob without re-JITing via
//!   [`crate::JitFunction::from_compiled_code`].
//! * **Emit a relocatable ELF object** (`.o`) file via [`CompiledCode::write_elf`] /
//!   [`CompiledCode::write_elf_to_file`].  The object carries a global symbol for every
//!   RISC-V instruction boundary so that `objdump -d` or a debugger can correlate each
//!   x86-64 sequence back to its originating RISC-V program counter.
//!
//! # Embedded function-pointer note
//!
//! The generated x86-64 code embeds absolute addresses of Rust functions (e.g. the
//! ECALL handler) as 64-bit immediates.  A blob saved from one process is therefore
//! only valid in a process where those functions are mapped at the **same** virtual
//! addresses.  In practice this means:
//!
//! * **Static binaries**: addresses are fixed – caching across runs is safe.
//! * **Shared-library / ASLR builds**: patching is required before calling the restored
//!   function.  See [`CompiledCode::patch_fn_ptr`].

use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

// ─── Core data structure ───────────────────────────────────────────────────

/// A snapshot of JIT-compiled x86-64 code that can be saved to disk and
/// later used to reconstruct a [`crate::JitFunction`] without re-transpiling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledCode {
    /// Raw x86-64 machine-code bytes.
    pub code: Vec<u8>,

    /// Byte offsets from the start of [`Self::code`], one per RISC-V
    /// instruction in program order.
    ///
    /// `jump_table[i]` is the offset at which the x86-64 sequence for the
    /// RISC-V instruction at `pc_base + i * 4` begins.
    pub jump_table: Vec<usize>,

    /// The program counter at which execution starts.
    pub pc_start: u64,

    /// The lowest RISC-V PC present in the program (= base of the jump table).
    pub pc_base: u64,

    /// Size (bytes) of the JIT virtual-memory region to allocate at runtime.
    pub memory_size: usize,

    /// Locations of embedded function-pointer immediates, used for patching
    /// when the code is restored in a different address space.
    ///
    /// Each entry is `(byte_offset_in_code, original_ptr_value)`.
    pub fn_ptr_relocations: Vec<(usize, u64)>,
}

// ─── Disk persistence ─────────────────────────────────────────────────────

impl CompiledCode {
    /// Serialize and write this blob to `path` (overwrites any existing file).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let bytes =
            bincode::serialize(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        File::create(path)?.write_all(&bytes)
    }

    /// Deserialize a blob previously written by [`Self::save`].
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        bincode::deserialize(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Patch a single embedded function pointer.
    ///
    /// `old_ptr` identifies the relocation entry; `new_ptr` is the address to
    /// write in its place.  The patch is applied as a little-endian `u64` at
    /// the stored byte offset.
    ///
    /// Returns `true` if at least one relocation was patched.
    pub fn patch_fn_ptr(&mut self, old_ptr: u64, new_ptr: u64) -> bool {
        let mut patched = false;
        for (offset, stored) in &mut self.fn_ptr_relocations {
            if *stored == old_ptr {
                let bytes = new_ptr.to_le_bytes();
                self.code[*offset..*offset + 8].copy_from_slice(&bytes);
                *stored = new_ptr;
                patched = true;
            }
        }
        patched
    }
}

// ─── ELF object-file emission ─────────────────────────────────────────────

/// ELF constants (x86-64 relocatable object).
mod elf_const {
    pub const ET_REL: u16 = 1;
    pub const EM_X86_64: u16 = 62;
    pub const EV_CURRENT: u32 = 1;
    pub const ELFCLASS64: u8 = 2;
    pub const ELFDATA2LSB: u8 = 1;
    pub const SHT_PROGBITS: u32 = 1;
    pub const SHT_SYMTAB: u32 = 2;
    pub const SHT_STRTAB: u32 = 3;
    pub const SHF_ALLOC: u64 = 2;
    pub const SHF_EXECINSTR: u64 = 4;
    pub const STB_LOCAL: u8 = 0;
    pub const STB_GLOBAL: u8 = 1;
    pub const STT_NOTYPE: u8 = 0;
    pub const STT_SECTION: u8 = 3;
    pub const ELF_HDR_SIZE: usize = 64;
    pub const SHDR_SIZE: usize = 64;
    pub const SYM_SIZE: usize = 24;
}

impl CompiledCode {
    /// Write an x86-64 ELF relocatable object (`.o`) to `writer`.
    ///
    /// The output contains:
    /// * A `.text` section with the raw machine code.
    /// * A global symbol `riscv_pc_0x{pc:08x}` for every RISC-V instruction,
    ///   pointing to the first byte of the corresponding x86-64 sequence.
    pub fn write_elf<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        use elf_const::*;

        // ── Build .shstrtab ──────────────────────────────────────────────
        let mut shstrtab = vec![0u8];
        let sh_text = append_str(&mut shstrtab, ".text");
        let sh_strtab = append_str(&mut shstrtab, ".strtab");
        let sh_symtab = append_str(&mut shstrtab, ".symtab");
        let sh_shstrtab = append_str(&mut shstrtab, ".shstrtab");

        // ── Build .strtab (symbol names) ─────────────────────────────────
        let mut strtab = vec![0u8];
        // Section symbol has no name (offset 0).
        let mut sym_name_offsets: Vec<u32> = Vec::with_capacity(self.jump_table.len());
        for i in 0..self.jump_table.len() {
            let pc = self.pc_base + i as u64 * 4;
            let name = format!("riscv_pc_0x{pc:08x}\0");
            sym_name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
        }

        // ── Build .symtab ────────────────────────────────────────────────
        // Layout: [NULL, .text-section-sym, ...global RISC-V PC syms...]
        let mut symtab: Vec<u8> = Vec::new();
        let num_local: u32 = 2; // NULL + section symbol

        write_sym(&mut symtab, 0, mk_info(STB_LOCAL, STT_NOTYPE), 0, 0, 0, 0);
        write_sym(&mut symtab, 0, mk_info(STB_LOCAL, STT_SECTION), 0, 1, 0, 0);
        for i in 0..self.jump_table.len() {
            write_sym(
                &mut symtab,
                sym_name_offsets[i],
                mk_info(STB_GLOBAL, STT_NOTYPE),
                0,
                1, // shndx = .text
                self.jump_table[i] as u64,
                0,
            );
        }

        // ── Compute file layout ──────────────────────────────────────────
        let text_off = ELF_HDR_SIZE;
        let text_sz = self.code.len();
        let strtab_off = align_up(text_off + text_sz, 1);
        let strtab_sz = strtab.len();
        let symtab_off = align_up(strtab_off + strtab_sz, 8);
        let symtab_sz = symtab.len();
        let shstrtab_off = align_up(symtab_off + symtab_sz, 1);
        let shstrtab_sz = shstrtab.len();
        let shdr_off = align_up(shstrtab_off + shstrtab_sz, 8);

        const NUM_SECTIONS: u16 = 5; // NULL, .text, .strtab, .symtab, .shstrtab
        const SHSTRTAB_IDX: u16 = 4;

        // ── ELF header ───────────────────────────────────────────────────
        let mut hdr = [0u8; ELF_HDR_SIZE];
        hdr[0..4].copy_from_slice(b"\x7fELF");
        hdr[4] = ELFCLASS64;
        hdr[5] = ELFDATA2LSB;
        hdr[6] = 1; // EI_VERSION
        hdr[16..18].copy_from_slice(&ET_REL.to_le_bytes());
        hdr[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        hdr[20..24].copy_from_slice(&EV_CURRENT.to_le_bytes());
        hdr[40..48].copy_from_slice(&(shdr_off as u64).to_le_bytes());
        hdr[52..54].copy_from_slice(&(ELF_HDR_SIZE as u16).to_le_bytes());
        hdr[58..60].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        hdr[60..62].copy_from_slice(&NUM_SECTIONS.to_le_bytes());
        hdr[62..64].copy_from_slice(&SHSTRTAB_IDX.to_le_bytes());

        // ── Section headers ──────────────────────────────────────────────
        let mut shdrs: Vec<u8> = Vec::with_capacity(NUM_SECTIONS as usize * SHDR_SIZE);
        // 0: NULL
        write_shdr(&mut shdrs, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        // 1: .text
        write_shdr(
            &mut shdrs,
            sh_text,
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            0,
            text_off as u64,
            text_sz as u64,
            0,
            0,
            16,
            0,
        );
        // 2: .strtab
        write_shdr(
            &mut shdrs,
            sh_strtab,
            SHT_STRTAB,
            0,
            0,
            strtab_off as u64,
            strtab_sz as u64,
            0,
            0,
            1,
            0,
        );
        // 3: .symtab  (link = .strtab = 2, info = first global index)
        write_shdr(
            &mut shdrs,
            sh_symtab,
            SHT_SYMTAB,
            0,
            0,
            symtab_off as u64,
            symtab_sz as u64,
            2,
            num_local,
            8,
            SYM_SIZE as u64,
        );
        // 4: .shstrtab
        write_shdr(
            &mut shdrs,
            sh_shstrtab,
            SHT_STRTAB,
            0,
            0,
            shstrtab_off as u64,
            shstrtab_sz as u64,
            0,
            0,
            1,
            0,
        );

        // ── Write to output ──────────────────────────────────────────────
        writer.write_all(&hdr)?;
        writer.write_all(&self.code)?;
        write_pad(writer, text_off + text_sz, strtab_off)?;
        writer.write_all(&strtab)?;
        write_pad(writer, strtab_off + strtab_sz, symtab_off)?;
        writer.write_all(&symtab)?;
        write_pad(writer, symtab_off + symtab_sz, shstrtab_off)?;
        writer.write_all(&shstrtab)?;
        write_pad(writer, shstrtab_off + shstrtab_sz, shdr_off)?;
        writer.write_all(&shdrs)?;

        Ok(())
    }

    /// Convenience wrapper: write an ELF object to the file at `path`.
    pub fn write_elf_to_file(&self, path: &Path) -> io::Result<()> {
        self.write_elf(&mut File::create(path)?)
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────

fn align_up(n: usize, align: usize) -> usize {
    if align <= 1 {
        n
    } else {
        (n + align - 1) & !(align - 1)
    }
}

/// Append a null-terminated string; return the start offset.
fn append_str(buf: &mut Vec<u8>, s: &str) -> u32 {
    let off = buf.len() as u32;
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
    off
}

const fn mk_info(binding: u8, typ: u8) -> u8 {
    (binding << 4) | (typ & 0xf)
}

fn write_sym(buf: &mut Vec<u8>, name: u32, info: u8, other: u8, shndx: u16, value: u64, size: u64) {
    buf.extend_from_slice(&name.to_le_bytes());
    buf.push(info);
    buf.push(other);
    buf.extend_from_slice(&shndx.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    buf: &mut Vec<u8>,
    name: u32,
    typ: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
) {
    buf.extend_from_slice(&name.to_le_bytes());
    buf.extend_from_slice(&typ.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&addr.to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&link.to_le_bytes());
    buf.extend_from_slice(&info.to_le_bytes());
    buf.extend_from_slice(&align.to_le_bytes());
    buf.extend_from_slice(&entsize.to_le_bytes());
}

fn write_pad<W: Write>(w: &mut W, current: usize, target: usize) -> io::Result<()> {
    if target > current {
        let zeros = vec![0u8; target - current];
        w.write_all(&zeros)?;
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_save_load() {
        let original = CompiledCode {
            code: vec![0x90, 0xC3], // NOP; RET
            jump_table: vec![0, 1],
            pc_start: 0x1000,
            pc_base: 0x1000,
            memory_size: 4096,
            fn_ptr_relocations: vec![],
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        original.save(&path).unwrap();

        let loaded = CompiledCode::load(&path).unwrap();
        assert_eq!(original.code, loaded.code);
        assert_eq!(original.jump_table, loaded.jump_table);
        assert_eq!(original.pc_start, loaded.pc_start);
        assert_eq!(original.pc_base, loaded.pc_base);
        assert_eq!(original.memory_size, loaded.memory_size);
    }

    #[test]
    fn elf_output_has_correct_magic() {
        let compiled = CompiledCode {
            code: vec![0x90, 0xC3],
            jump_table: vec![0],
            pc_start: 0x1000,
            pc_base: 0x1000,
            memory_size: 4096,
            fn_ptr_relocations: vec![],
        };

        let mut out = Vec::new();
        compiled.write_elf(&mut out).unwrap();

        // ELF magic
        assert_eq!(&out[0..4], b"\x7fELF");
        // ELFCLASS64
        assert_eq!(out[4], 2);
        // ELFDATA2LSB
        assert_eq!(out[5], 1);
        // ET_REL
        assert_eq!(u16::from_le_bytes([out[16], out[17]]), 1);
        // EM_X86_64
        assert_eq!(u16::from_le_bytes([out[18], out[19]]), 62);
    }

    #[test]
    fn patch_fn_ptr_updates_code_and_reloc() {
        let old_addr: u64 = 0xDEAD_BEEF_0000_0000;
        let new_addr: u64 = 0x1234_5678_9ABC_DEF0;

        // A fake code buffer with the old address embedded at offset 2.
        let mut code = vec![0x48u8, 0xB8]; // REX.W MOV rax, imm64 prefix
        code.extend_from_slice(&old_addr.to_le_bytes());
        code.push(0xFF); // trailing dummy byte

        let mut compiled = CompiledCode {
            code,
            jump_table: vec![],
            pc_start: 0,
            pc_base: 0,
            memory_size: 0,
            fn_ptr_relocations: vec![(2, old_addr)],
        };

        let patched = compiled.patch_fn_ptr(old_addr, new_addr);
        assert!(patched);
        assert_eq!(&compiled.code[2..10], &new_addr.to_le_bytes());
        assert_eq!(compiled.fn_ptr_relocations[0].1, new_addr);
    }
}
