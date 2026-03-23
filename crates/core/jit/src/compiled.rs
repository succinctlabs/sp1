//! Serializable, persistent representation of JIT-compiled x86-64 code.
//!
//! [`CompiledCode`] lets you:
//! * **Cache** a JIT compilation result to disk and reload it later with
//!   [`CompiledCode::save`] / [`CompiledCode::load`].
//! * **Reconstruct** a [`crate::JitFunction`] from a cached blob without re-JITing via
//!   [`crate::JitFunction::from_compiled_code`].
//! * **Emit a GAS-compatible assembly file** (`.S`) via [`CompiledCode::write_asm`] /
//!   [`CompiledCode::write_asm_to_file`].  The file carries a global symbol for every
//!   RISC-V instruction boundary so that a profiler or debugger can correlate each
//!   x86-64 sequence back to its originating RISC-V program counter.  Assemble with
//!   `as -o out.o out.S` or `clang -c -o out.o out.S`, then link normally.
//!
//! # ECALL handler patching
//!
//! The generated x86-64 code embeds the ECALL handler address as a 64-bit immediate.
//! [`CompiledCode::ecall_ptr_offsets`] records where those immediates live so that
//! [`crate::JitFunction::from_compiled_code`] can overwrite them with the correct
//! handler address before making the buffer executable.
//!
//! Only JIT code that exclusively calls the ECALL handler (no other external function
//! calls) can be serialised.  The transpiler enforces this at [`into_compiled_code`]
//! time and returns an error otherwise.

use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

// ─── Core data structure ───────────────────────────────────────────────────

/// A snapshot of JIT-compiled x86-64 code that can be saved to disk and
/// later used to reconstruct a [`crate::JitFunction`] without re-transpiling.
///
/// Only JIT code that calls **no** external functions other than the ECALL
/// handler can be serialised; the transpiler returns an error otherwise.
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

    /// Byte offsets within [`Self::code`] where the ECALL handler address is
    /// embedded as a little-endian 64-bit immediate (`mov rax, imm64`).
    ///
    /// [`crate::JitFunction::from_compiled_code`] overwrites each location with
    /// the live handler address before marking the buffer executable.
    pub ecall_ptr_offsets: Vec<usize>,

    /// Byte offsets within [`Self::code`] where the UNIMP handler address is
    /// embedded as a little-endian 64-bit immediate (`mov rax, imm64`).
    ///
    /// [`crate::JitFunction::from_compiled_code`] overwrites each location with
    /// the live handler address before marking the buffer executable.
    pub unimp_ptr_offsets: Vec<usize>,

    /// The `max_trace_size` value at transpile time.
    pub max_trace_size: u64,
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
}

// ─── Assembly-source emission ─────────────────────────────────────────────

impl CompiledCode {
    /// Write a GAS-compatible x86-64 assembly file (`.S`) to `writer`.
    ///
    /// The output contains:
    ///
    /// 1. A **`.text` section** with the raw machine code expressed as `.byte` directives,
    ///    a global `sp1_jit_code` label at position 0 (the function entry point), and a
    ///    `.global` label at the start of every RISC-V instruction's x86-64 sequence:
    ///
    ///    ```text
    ///    sp1_jit_code:                            # ← entry point (prologue starts here)
    ///        .byte 0x55,0x48,...                  # prologue bytes
    ///    riscv_pc_0x00010000:
    ///        .byte 0x0f,0x1f,0x80,0x00,0x00,0x00,0x00  # 7-byte NOP (PIE-safe padding)
    ///        .byte 0xe8                           # CALL rel32 opcode
    ///        .long sp1_ecall_handler - . - 4      # R_X86_64_PC32 ← linker resolves
    ///    ```
    ///
    ///    The original `MOV rax, imm64 + CALL rax` sequence (12 bytes) produced by the
    ///    JIT is replaced in its entirety by `7-byte NOP + CALL rel32` (also 12 bytes).
    ///    The `.long symbol - . - 4` expression emits an `R_X86_64_PC32` relocation,
    ///    which lld accepts in `.text` for both PIE and non-PIE executables — unlike
    ///    `.quad symbol` (`R_X86_64_64`) which lld rejects in a read-only `.text` section.
    ///
    /// 2. A **`.rodata` section** carrying all remaining [`CompiledCode`] fields as
    ///    named, globally-visible symbols:
    ///
    ///    | Symbol                      | Content                                              |
    ///    |-----------------------------|------------------------------------------------------|
    ///    | `sp1_jump_table`            | Array of `u64` byte offsets from `sp1_jit_code`      |
    ///    | `sp1_jump_table_len`        | `u64` — number of entries                            |
    ///    | `sp1_ecall_ptr_offsets`     | Array of `u64` byte offsets (patch sites)            |
    ///    | `sp1_ecall_ptr_offsets_len` | `u64` — number of entries                            |
    ///    | `sp1_unimp_ptr_offsets`     | Array of `u64` byte offsets (patch sites)            |
    ///    | `sp1_unimp_ptr_offsets_len` | `u64` — number of entries                            |
    ///    | `sp1_pc_start`              | `u64` — starting program counter                     |
    ///    | `sp1_pc_base`               | `u64` — base program counter (jump-table origin)     |
    ///    | `sp1_memory_size`           | `u64` — VM memory region size in bytes               |
    ///    | `sp1_max_trace_size`        | `u64` — Max trace size (number of entries)           |
    ///
    ///    `sp1_jump_table` entries are emitted as `.quad riscv_pc_0x… - sp1_jit_code`.
    ///    Because both symbols live in the same `.text` section of the same object file,
    ///    GAS computes the difference as a **compile-time constant** and emits **no
    ///    relocation** — making the object compatible with PIE executables and shared
    ///    libraries.  At runtime, [`crate::JitFunction::from_static_link`] adds the
    ///    load address of `sp1_jit_code` to each entry to recover the absolute pointer.
    ///
    /// # Parameters
    /// - `ecall_symbol`: the linker symbol name of the ECALL handler function
    ///   (e.g. `"sp1_ecall_handler"`).  The function must be exported from the
    ///   binary with that exact name (use `#[no_mangle]`).
    /// - `unimp_symbol`: the linker symbol name of the UNIMP handler function
    ///   (e.g. `"sp1_unimp_handler"`).  Same export requirement applies.
    ///
    /// # Assembling and linking
    /// ```sh
    /// as -o out.o out.S          # GNU Binutils
    /// clang -c -o out.o out.S    # LLVM / Clang
    /// ```
    /// Then link `out.o` together with the object that exports `sp1_ecall_handler` and
    /// `sp1_unimp_handler`.  With the `static-link` feature enabled in `sp1-jit` and
    /// `sp1-core-executor`, [`crate::MinimalExecutor::from_static_link`] can bootstrap
    /// the VM directly from those linked symbols without any runtime deserialization.
    pub fn write_asm<W: Write>(
        &self,
        writer: &mut W,
        ecall_symbol: &str,
        unimp_symbol: &str,
    ) -> io::Result<()> {
        use std::collections::BTreeMap;

        // Unified map: code offset → symbol name for every patchable pointer slot.
        // Both ECALL and UNIMP handler addresses are emitted via a PIE-safe CALL rel32
        // sequence (see the walk loop below for details).
        let mut ptr_sites: BTreeMap<usize, &str> = BTreeMap::new();
        for &off in &self.ecall_ptr_offsets {
            ptr_sites.insert(off, ecall_symbol);
        }
        for &off in &self.unimp_ptr_offsets {
            ptr_sites.insert(off, unimp_symbol);
        }

        // Sorted list of (code_offset, label_name), one per RISC-V instruction.
        let mut labels: Vec<(usize, String)> = self
            .jump_table
            .iter()
            .enumerate()
            .map(|(i, &off)| {
                let pc = self.pc_base + i as u64 * 4;
                (off, format!("riscv_pc_0x{pc:08x}"))
            })
            .collect();
        labels.sort_unstable_by_key(|(off, _)| *off);

        // ── .text section ────────────────────────────────────────────────
        writeln!(writer, "\t.section\t.text,\"ax\",@progbits")?;
        writeln!(writer)?;
        // Entry-point label visible to the static-link feature.
        writeln!(writer, "\t.global\tsp1_jit_code")?;
        writeln!(writer, "\t.type\tsp1_jit_code, @function")?;
        for (_, name) in &labels {
            writeln!(writer, "\t.global\t{name}")?;
        }
        writeln!(writer)?;
        // sp1_jit_code sits at offset 0 — before any per-instruction label.
        writeln!(writer, "sp1_jit_code:")?;

        // ── Body: walk the code buffer, emitting labels / call-stubs / .byte ──
        //
        // Handler call-site layout produced by call_extern_fn_raw (12 bytes total):
        //
        //   [ptr_site - 2]  0x48, 0xB8         REX.W + MOV rax opcode (preamble)
        //   [ptr_site]      <8-byte imm64>      absolute handler address (the patch slot)
        //   [ptr_site + 8]  0xFF, 0xD0         CALL rax (postamble)
        //
        // Emitting `.quad symbol` at ptr_site produces R_X86_64_64 — an absolute
        // 64-bit relocation that lld rejects in a PIE executable's read-only .text
        // section.  Instead the entire 12-byte window is replaced with a PIE-safe
        // sequence of equal length:
        //
        //   7-byte NOP  (0x0F 0x1F 0x80 0x00 0x00 0x00 0x00)
        //   CALL rel32  (0xE8 + .long symbol - . - 4)
        //
        // The `.long symbol - . - 4` expression produces R_X86_64_PC32, which lld
        // accepts unconditionally in .text for both PIE and non-PIE binaries.
        // The from_compiled_code restore path is unaffected: it patches the 8-byte
        // absolute immediate in a freshly allocated, writable mmap buffer where
        // R_X86_64_64 is fine.

        // Byte counts for the MOV rax, imm64 / CALL rax sequence.
        const CALL_PREAMBLE: usize = 2; // REX.W (0x48) + B8+rd opcode (0xB8)
        const CALL_IMM: usize = 8; // 64-bit immediate — the patchable slot
        const CALL_POSTAMBLE: usize = 2; // CALL rax (0xFF 0xD0)
        const CALL_SEQ: usize = CALL_PREAMBLE + CALL_IMM + CALL_POSTAMBLE; // 12

        let mut label_iter = labels.iter().peekable();
        let mut pos = 0usize;

        while pos < self.code.len() {
            // Emit any label(s) sitting at this position.
            while label_iter.peek().map(|(off, _)| *off) == Some(pos) {
                let (_, name) = label_iter.next().unwrap();
                writeln!(writer, "{name}:")?;
            }

            // Check for a handler call site whose preamble (MOV rax prefix) starts
            // at `pos`.  The imm64 patch slot lives at pos + CALL_PREAMBLE; the
            // full 12-byte window must fit within the code buffer.
            if pos + CALL_SEQ <= self.code.len() {
                if let Some(&symbol) = ptr_sites.get(&(pos + CALL_PREAMBLE)) {
                    debug_assert_eq!(
                        &self.code[pos..pos + CALL_PREAMBLE],
                        &[0x48, 0xb8],
                        "expected REX.W + MOV rax preamble at offset {pos}",
                    );
                    debug_assert_eq!(
                        &self.code[pos + CALL_PREAMBLE + CALL_IMM
                            ..pos + CALL_PREAMBLE + CALL_IMM + CALL_POSTAMBLE],
                        &[0xff, 0xd0],
                        "expected CALL rax postamble at offset {}",
                        pos + CALL_PREAMBLE + CALL_IMM,
                    );
                    // Emit PIE-safe 12-byte replacement:
                    //   7-byte NOP covers the preamble + first 5 bytes of imm64.
                    //   CALL rel32 covers the remaining 3 imm64 bytes + CALL rax.
                    // R_X86_64_PC32 is accepted by lld in .text for PIE binaries.
                    writeln!(writer, "\t.byte\t0x0f,0x1f,0x80,0x00,0x00,0x00,0x00")?;
                    writeln!(writer, "\t.byte\t0xe8")?;
                    writeln!(writer, "\t.long\t{symbol} - . - 4")?;
                    pos += CALL_SEQ;
                    continue;
                }
            }

            // Plain bytes: stop CALL_PREAMBLE bytes before the next ptr_site so
            // that its preamble bytes are included in the special-emission window.
            let next_label = label_iter.peek().map(|(off, _)| *off);
            let next_ptr = ptr_sites
                .range(pos + 1..)
                .next()
                .map(|(&off, _)| off.saturating_sub(CALL_PREAMBLE));
            let run_end =
                [next_label, next_ptr, Some(self.code.len())].into_iter().flatten().min().unwrap();
            // Guarantee forward progress for degenerate cases (ptr_site < CALL_PREAMBLE).
            let run_end = run_end.max(pos + 1);

            for chunk in self.code[pos..run_end].chunks(8) {
                let hex: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
                writeln!(writer, "\t.byte\t{}", hex.join(","))?;
            }
            pos = run_end;
        }

        // ── .rodata section — all remaining CompiledCode fields ───────────
        writeln!(writer)?;
        writeln!(writer, "\t.section\t.rodata")?;
        writeln!(writer)?;

        // ── jump_table: byte offsets from sp1_jit_code ───────────────────
        // Entries are emitted as `.quad riscv_pc_0x… - sp1_jit_code`.
        // Both symbols are in the same .text section, so GAS resolves the
        // difference to a plain integer constant at assembly time — no
        // relocation is emitted, making the object compatible with PIE/PIC.
        // from_static_link() recovers the absolute pointer by adding the
        // runtime address of sp1_jit_code, mirroring what JitFunction::new()
        // does for the dynamic path.
        writeln!(writer, "\t.global\tsp1_jump_table")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_jump_table:")?;
        for (_, name) in &labels {
            writeln!(writer, "\t.quad\t{name} - sp1_jit_code")?;
        }
        writeln!(writer)?;
        writeln!(writer, "\t.global\tsp1_jump_table_len")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_jump_table_len:")?;
        writeln!(writer, "\t.quad\t{}", self.jump_table.len())?;
        writeln!(writer)?;

        // ── ecall_ptr_offsets ─────────────────────────────────────────────
        writeln!(writer, "\t.global\tsp1_ecall_ptr_offsets")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_ecall_ptr_offsets:")?;
        for &off in &self.ecall_ptr_offsets {
            writeln!(writer, "\t.quad\t{off}")?;
        }
        writeln!(writer)?;
        writeln!(writer, "\t.global\tsp1_ecall_ptr_offsets_len")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_ecall_ptr_offsets_len:")?;
        writeln!(writer, "\t.quad\t{}", self.ecall_ptr_offsets.len())?;
        writeln!(writer)?;

        // ── unimp_ptr_offsets ─────────────────────────────────────────────
        writeln!(writer, "\t.global\tsp1_unimp_ptr_offsets")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_unimp_ptr_offsets:")?;
        for &off in &self.unimp_ptr_offsets {
            writeln!(writer, "\t.quad\t{off}")?;
        }
        writeln!(writer)?;
        writeln!(writer, "\t.global\tsp1_unimp_ptr_offsets_len")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_unimp_ptr_offsets_len:")?;
        writeln!(writer, "\t.quad\t{}", self.unimp_ptr_offsets.len())?;
        writeln!(writer)?;

        // ── scalar constants ──────────────────────────────────────────────
        writeln!(writer, "\t.global\tsp1_pc_start")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_pc_start:")?;
        writeln!(writer, "\t.quad\t{}", self.pc_start)?;
        writeln!(writer)?;

        writeln!(writer, "\t.global\tsp1_pc_base")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_pc_base:")?;
        writeln!(writer, "\t.quad\t{}", self.pc_base)?;
        writeln!(writer)?;

        writeln!(writer, "\t.global\tsp1_memory_size")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_memory_size:")?;
        writeln!(writer, "\t.quad\t{}", self.memory_size)?;

        writeln!(writer, "\t.global\tsp1_max_trace_size")?;
        writeln!(writer, "\t.align\t8")?;
        writeln!(writer, "sp1_max_trace_size:")?;
        writeln!(writer, "\t.quad\t{}", self.max_trace_size)?;

        Ok(())
    }

    /// Convenience wrapper: write a `.S` assembly file to `path`.
    ///
    /// See [`Self::write_asm`] for the `ecall_symbol` and `unimp_symbol` parameters.
    pub fn write_asm_to_file(
        &self,
        path: &Path,
        ecall_symbol: &str,
        unimp_symbol: &str,
    ) -> io::Result<()> {
        self.write_asm(&mut File::create(path)?, ecall_symbol, unimp_symbol)
    }
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
            max_trace_size: 7777,
            ecall_ptr_offsets: vec![],
            unimp_ptr_offsets: vec![],
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
        assert_eq!(original.max_trace_size, loaded.max_trace_size);
        assert_eq!(original.ecall_ptr_offsets, loaded.ecall_ptr_offsets);
        assert_eq!(original.unimp_ptr_offsets, loaded.unimp_ptr_offsets);
    }

    #[test]
    fn asm_output_structure() {
        // 22-byte code buffer (realistic layout matching call_extern_fn_raw output):
        //   [0..4]   regular bytes for instruction at pc 0x1000
        //   [4..6]   REX.W + MOV rax opcode (0x48, 0xb8)  — call-site preamble
        //   [6..14]  ecall handler imm64 slot (ecall_ptr_offsets = [6])
        //   [14..16] CALL rax (0xff, 0xd0)                — call-site postamble
        //   [16..22] regular bytes for instruction at pc 0x1004
        let mut code = vec![0xf4u8; 22];
        code[4] = 0x48;
        code[5] = 0xb8;
        // imm64 slot [6..14] stays as 0xf4 (dummy handler address)
        code[14] = 0xff; // CALL rax
        code[15] = 0xd0;

        let compiled = CompiledCode {
            code,
            jump_table: vec![0, 16], // second instruction starts after the 12-byte call site
            pc_start: 0x1000,
            pc_base: 0x1000,
            memory_size: 4096,
            max_trace_size: 7777,
            ecall_ptr_offsets: vec![6],
            unimp_ptr_offsets: vec![],
        };

        let mut out = Vec::new();
        compiled.write_asm(&mut out, "sp1_ecall_handler", "sp1_unimp_handler").unwrap();
        let text = String::from_utf8(out).unwrap();

        // Section declaration present.
        assert!(text.contains(".section\t.text,\"ax\",@progbits"), "missing section directive");

        // Entry-point label present in .text and declared global.
        assert!(text.contains(".global\tsp1_jit_code"), "missing .global sp1_jit_code");
        assert!(text.contains("sp1_jit_code:"), "missing sp1_jit_code label def");

        // Both per-instruction labels declared global and defined.
        assert!(text.contains(".global\triscv_pc_0x00001000"), "missing global for pc 0x1000");
        assert!(text.contains(".global\triscv_pc_0x00001004"), "missing global for pc 0x1004");
        assert!(text.contains("riscv_pc_0x00001000:"), "missing label def for pc 0x1000");
        assert!(text.contains("riscv_pc_0x00001004:"), "missing label def for pc 0x1004");

        // ECALL call site must be emitted as a PIE-safe NOP + CALL rel32, NOT as .quad.
        // The 12-byte window [MOV rax, imm64 + CALL rax] is replaced with:
        //   7-byte NOP  → harmless padding
        //   CALL rel32  → R_X86_64_PC32, accepted by lld in .text of PIE binaries
        let text_section_end = text.find(".section\t.rodata").unwrap();
        let text_section = &text[..text_section_end];

        assert!(
            text_section.contains("0x0f,0x1f,0x80,0x00,0x00,0x00,0x00"),
            "missing 7-byte NOP in ecall call site"
        );
        assert!(text_section.contains("0xe8"), "missing CALL rel32 opcode in ecall call site");
        assert!(
            text_section.contains("sp1_ecall_handler - . - 4"),
            "missing PC-relative offset expression for ecall handler"
        );

        // Absolute .quad of the handler symbol must NOT appear in .text — it would
        // produce R_X86_64_64 which lld rejects in a PIE executable's .text section.
        assert!(
            !text_section.contains(".quad\tsp1_ecall_handler"),
            ".quad sp1_ecall_handler must not appear in .text (produces R_X86_64_64)"
        );

        // The MOV rax preamble bytes (0x48, 0xb8) are consumed by the special-emission
        // window and must not appear as standalone .byte directives in .text.
        assert!(
            !text_section.contains("0x48,0xb8"),
            "REX.W + MOV rax prefix must not appear as raw .byte (consumed by call-site emission)"
        );

        // The 8 imm64 slot bytes (all 0xf4) must not appear as raw .byte — they are
        // absorbed into the NOP+CALL replacement.
        assert!(
            !text[..text.find("riscv_pc_0x00001004:").unwrap()]
                .contains(".byte\t0xf4,0xf4,0xf4,0xf4,0xf4,0xf4,0xf4,0xf4"),
            "ecall pointer bytes leaked as raw .byte"
        );

        // .rodata section present with all metadata symbols.
        assert!(text.contains(".section\t.rodata"), "missing .rodata section");
        assert!(text.contains("sp1_jump_table:"), "missing sp1_jump_table");
        assert!(text.contains("sp1_jump_table_len:"), "missing sp1_jump_table_len");
        assert!(text.contains("sp1_ecall_ptr_offsets:"), "missing sp1_ecall_ptr_offsets");
        assert!(text.contains("sp1_ecall_ptr_offsets_len:"), "missing sp1_ecall_ptr_offsets_len");
        assert!(text.contains("sp1_unimp_ptr_offsets:"), "missing sp1_unimp_ptr_offsets");
        assert!(text.contains("sp1_unimp_ptr_offsets_len:"), "missing sp1_unimp_ptr_offsets_len");
        assert!(text.contains("sp1_pc_start:"), "missing sp1_pc_start");
        assert!(text.contains("sp1_pc_base:"), "missing sp1_pc_base");
        assert!(text.contains("sp1_memory_size:"), "missing sp1_memory_size");
        assert!(text.contains("sp1_max_trace_size:"), "missing sp1_max_trace_size");

        // jump_table entries are relative offsets from sp1_jit_code (no
        // absolute relocations — required for PIE/PIC compatibility).
        let rodata_start = text.find(".section\t.rodata").unwrap();
        let rodata = &text[rodata_start..];
        assert!(
            rodata.contains(".quad\triscv_pc_0x00001000 - sp1_jit_code"),
            "jump table entry should be a relative offset from sp1_jit_code"
        );
        assert!(
            rodata.contains(".quad\triscv_pc_0x00001004 - sp1_jit_code"),
            "jump table entry should be a relative offset from sp1_jit_code"
        );
        // Absolute symbol references must NOT appear in the jump table (they
        // would produce R_X86_64_64 relocations, incompatible with PIE/PIC).
        assert!(
            !rodata[..rodata.find("sp1_jump_table_len:").unwrap()]
                .contains(".quad\triscv_pc_0x00001000\n"),
            "absolute jump table entry must not be emitted"
        );

        // Scalar constants carry the right values.
        assert!(text.contains("\t.quad\t4096"), "pc_start or memory_size value not found");
    }

    #[test]
    fn ecall_and_unimp_ptr_offsets_roundtrip() {
        // Simulate a code buffer with one ECALL and one UNIMP handler pointer.
        let handler_addr: u64 = 0xDEAD_BEEF_0000_0001;
        let mut code = vec![0u8; 32];
        code[2..10].copy_from_slice(&handler_addr.to_le_bytes());
        code[18..26].copy_from_slice(&handler_addr.to_le_bytes());

        let compiled = CompiledCode {
            code,
            jump_table: vec![0],
            pc_start: 0x1000,
            pc_base: 0x1000,
            memory_size: 4096,
            max_trace_size: 7777,
            ecall_ptr_offsets: vec![2],
            unimp_ptr_offsets: vec![18],
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        compiled.save(&path).unwrap();

        let loaded = CompiledCode::load(&path).unwrap();
        assert_eq!(loaded.ecall_ptr_offsets, vec![2]);
        assert_eq!(loaded.unimp_ptr_offsets, vec![18]);
    }
}
