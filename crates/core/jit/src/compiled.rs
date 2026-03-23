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
    /// The output contains a `.text` section with the raw machine code expressed
    /// as `.byte` directives, with a `.global` label at the start of every
    /// RISC-V instruction's x86-64 sequence:
    ///
    /// ```text
    /// riscv_pc_0x00010000:
    ///     .byte 0x55,0x48,0x89,0xe5   # prologue bytes
    ///     .byte 0x48,0xb8             # REX.W + MOV rax, imm64
    ///     .quad sp1_ecall_handler     # <- linker fills the handler address
    ///     .byte 0xff,0xd0             # CALL rax
    /// ```
    ///
    /// At every byte offset listed in [`Self::ecall_ptr_offsets`] the 8 bytes
    /// that hold the embedded handler address are emitted as
    /// `.quad <ecall_symbol>` instead of raw `.byte` values.  The assembler
    /// records a proper `R_X86_64_64` relocation so the linker fills in the
    /// correct absolute address at link time.
    ///
    /// # Parameters
    /// - `ecall_symbol`: the linker symbol name of the ECALL handler function
    ///   (e.g. `"sp1_ecall_handler"`).  The function must be exported from the
    ///   binary with that exact name (use `#[no_mangle]`).
    ///
    /// # Assembling
    /// ```sh
    /// as -o out.o out.S          # GNU Binutils
    /// clang -c -o out.o out.S    # LLVM / Clang
    /// ```
    pub fn write_asm<W: Write>(&self, writer: &mut W, ecall_symbol: &str) -> io::Result<()> {
        use std::collections::BTreeSet;

        // Sorted set of offsets where .quad replaces 8 raw bytes.
        let ecall_set: BTreeSet<usize> = self.ecall_ptr_offsets.iter().copied().collect();

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

        // ── Header ───────────────────────────────────────────────────────
        writeln!(writer, "\t.section\t.text,\"ax\",@progbits")?;
        writeln!(writer)?;
        for (_, name) in &labels {
            writeln!(writer, "\t.global\t{name}")?;
        }
        writeln!(writer)?;

        // ── Body: walk the code buffer, emitting labels / .quad / .byte ──
        let mut label_iter = labels.iter().peekable();
        let mut pos = 0usize;

        while pos < self.code.len() {
            // Emit any label(s) sitting at this position.
            while label_iter.peek().map(|(off, _)| *off) == Some(pos) {
                let (_, name) = label_iter.next().unwrap();
                writeln!(writer, "{name}:")?;
            }

            // ECALL relocation site: emit a symbol reference instead of bytes.
            if ecall_set.contains(&pos) {
                writeln!(writer, "\t.quad\t{ecall_symbol}")?;
                pos += 8;
                continue;
            }

            // Plain bytes: run until the next label or ecall site.
            let next_label = label_iter.peek().map(|(off, _)| *off);
            let next_ecall = ecall_set.range(pos + 1..).next().copied();
            let run_end = [next_label, next_ecall, Some(self.code.len())]
                .into_iter()
                .flatten()
                .min()
                .unwrap();

            for chunk in self.code[pos..run_end].chunks(8) {
                let hex: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
                writeln!(writer, "\t.byte\t{}", hex.join(","))?;
            }
            pos = run_end;
        }

        Ok(())
    }

    /// Convenience wrapper: write a `.S` assembly file to `path`.
    ///
    /// See [`Self::write_asm`] for the `ecall_symbol` parameter.
    pub fn write_asm_to_file(&self, path: &Path, ecall_symbol: &str) -> io::Result<()> {
        self.write_asm(&mut File::create(path)?, ecall_symbol)
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
            ecall_ptr_offsets: vec![],
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
        assert_eq!(original.ecall_ptr_offsets, loaded.ecall_ptr_offsets);
    }

    #[test]
    fn asm_output_structure() {
        // 20-byte code buffer:
        //   [0..4]   regular bytes for instruction at pc 0x1000
        //   [4..6]   REX.W + MOV rax opcode (0x48, 0xb8)
        //   [6..14]  ecall handler pointer (ecall_ptr_offsets = [6])
        //   [14..20] regular bytes for instruction at pc 0x1004
        let mut code = vec![0xf4u8; 20];
        code[4] = 0x48;
        code[5] = 0xb8;

        let compiled = CompiledCode {
            code,
            jump_table: vec![0, 14],
            pc_start: 0x1000,
            pc_base: 0x1000,
            memory_size: 4096,
            ecall_ptr_offsets: vec![6],
        };

        let mut out = Vec::new();
        compiled.write_asm(&mut out, "sp1_ecall_handler").unwrap();
        let text = String::from_utf8(out).unwrap();

        // Section declaration present.
        assert!(text.contains(".section\t.text,\"ax\",@progbits"), "missing section directive");

        // Both labels declared global and defined.
        assert!(text.contains(".global\triscv_pc_0x00001000"), "missing global for pc 0x1000");
        assert!(text.contains(".global\triscv_pc_0x00001004"), "missing global for pc 0x1004");
        assert!(text.contains("riscv_pc_0x00001000:"), "missing label def for pc 0x1000");
        assert!(text.contains("riscv_pc_0x00001004:"), "missing label def for pc 0x1004");

        // ECALL handler emitted as a symbol reference, not raw bytes.
        assert!(text.contains(".quad\tsp1_ecall_handler"), "missing .quad for ecall handler");

        // The two REX.W + opcode bytes that precede the pointer are plain .byte.
        assert!(text.contains("0x48,0xb8"), "missing REX.W + MOV-rax opcode bytes");

        // The 8 bytes of the pointer slot must NOT appear as raw .byte values.
        // (They are all 0xf4 in our dummy buffer, but they are replaced by .quad.)
        let lines_with_f4_after_ecall: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.contains("riscv_pc_0x00001004"))
            .filter(|l| l.contains("0xf4"))
            .collect();
        // Only the post-ecall instruction bytes (riscv_pc_0x1004 region) may contain 0xf4.
        // The ecall slot itself must not have been emitted as .byte.
        assert!(
            !text[..text.find("riscv_pc_0x00001004:").unwrap()]
                .contains(".byte\t0xf4,0xf4,0xf4,0xf4,0xf4,0xf4,0xf4,0xf4"),
            "ecall pointer bytes leaked as raw .byte"
        );
        let _ = lines_with_f4_after_ecall; // used above
    }

    #[test]
    fn ecall_ptr_offsets_roundtrip() {
        // Simulate a code buffer with two embedded ECALL handler pointers.
        let handler_addr: u64 = 0xDEAD_BEEF_0000_0001;
        let mut code = vec![0u8; 32];
        // Write fake handler address at offsets 2 and 18.
        code[2..10].copy_from_slice(&handler_addr.to_le_bytes());
        code[18..26].copy_from_slice(&handler_addr.to_le_bytes());

        let compiled = CompiledCode {
            code,
            jump_table: vec![0],
            pc_start: 0x1000,
            pc_base: 0x1000,
            memory_size: 4096,
            ecall_ptr_offsets: vec![2, 18],
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        compiled.save(&path).unwrap();

        let loaded = CompiledCode::load(&path).unwrap();
        assert_eq!(loaded.ecall_ptr_offsets, vec![2, 18]);
    }
}
