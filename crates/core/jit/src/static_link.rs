//! Static-link support for [`crate::JitFunction`].
//!
//! When a [`crate::CompiledCode`] is written to a `.S` file via
//! [`crate::CompiledCode::write_asm`] and assembled into an `.o` object, all
//! fields of the compiled program are exposed as global linker symbols:
//!
//! | Symbol                      | Type                    | Content                              |
//! |-----------------------------|-------------------------|--------------------------------------|
//! | `sp1_jit_code`              | function                | JIT prologue / entry point           |
//! | `sp1_jump_table`            | `[u64]`                 | Byte offsets from `sp1_jit_code`     |
//! | `sp1_jump_table_len`        | `u64`                   | Number of jump-table entries         |
//! | `sp1_ecall_ptr_offsets`     | `[u64]`                 | ECALL patch-site offsets             |
//! | `sp1_ecall_ptr_offsets_len` | `u64`                   | Number of ECALL patch sites          |
//! | `sp1_unimp_ptr_offsets`     | `[u64]`                 | UNIMP patch-site offsets             |
//! | `sp1_unimp_ptr_offsets_len` | `u64`                   | Number of UNIMP patch sites          |
//! | `sp1_pc_start`              | `u64`                   | Starting program counter             |
//! | `sp1_pc_base`               | `u64`                   | Base program counter                 |
//! | `sp1_memory_size`           | `u64`                   | VM memory region size in bytes       |
//!
//! This module declares those symbols as `extern "C"` so the Rust compiler
//! knows they exist; the linker resolves their addresses when the final binary
//! is built from `out.o` (produced by `as` or `clang -c`).
//!
//! # Usage
//! ```sh
//! # 1. Emit the assembly file from your compiled program:
//! #    (call CompiledCode::write_asm_to_file in a build step)
//!
//! # 2. Assemble:
//! as -o out.o out.S          # or: clang -c -o out.o out.S
//!
//! # 3. Link with your binary:
//! #    Add out.o to the link inputs (e.g. via build.rs or a linker script).
//!
//! # 4. Enable the feature and call:
//! #    MinimalExecutor::from_static_link(program, max_trace_size)
//! ```

use crate::JitContext;

// ---------------------------------------------------------------------------
// Extern declarations — filled in by the linker when out.o is linked in.
// ---------------------------------------------------------------------------

// `JitContext` contains Rust-only fields (e.g. `VecDeque`), which triggers the
// `improper_ctypes` lint.  The pointer is never actually passed across a real
// C boundary — it is only used within the same binary — so the lint is a
// false positive here.
#[allow(improper_ctypes)]
extern "C" {
    /// The JIT entry-point function.  Its address is the start of the code
    /// buffer (offset 0 — the prologue), which is what [`crate::JitFunction::call`]
    /// normally derives from the owned [`dynasmrt::ExecutableBuffer`].
    pub fn sp1_jit_code(ctx: *mut JitContext);

    /// First element of the jump-table array.
    ///
    /// Each entry holds a **byte offset from `sp1_jit_code`** — emitted in the
    /// `.S` file as `.quad riscv_pc_0x… - sp1_jit_code`.  Because both symbols
    /// are in the same `.text` section, GAS computes the difference at assembly
    /// time and emits no relocation, keeping the object PIE/PIC-compatible.
    ///
    /// [`crate::JitFunction::from_static_link`] converts each offset back to an
    /// absolute pointer by adding the runtime address of `sp1_jit_code`, exactly
    /// mirroring what [`crate::JitFunction::new`] does for the dynamic path.
    ///
    /// Declared as a zero-length array so that `sp1_jump_table.as_ptr()` yields
    /// a `*const u64` to the first entry without any extra indirection.
    pub static sp1_jump_table: [u64; 0];

    /// Number of entries in [`sp1_jump_table`].
    pub static sp1_jump_table_len: u64;

    /// First element of the ECALL handler patch-site offset array.
    ///
    /// In the static-link case these offsets are informational only: the linker
    /// has already resolved the `R_X86_64_PC32` relocations emitted by
    /// [`crate::CompiledCode::write_asm`] in the `.text` section,
    /// so no runtime patching is required.
    pub static sp1_ecall_ptr_offsets: [u64; 0];
    /// Number of entries in [`sp1_ecall_ptr_offsets`].
    pub static sp1_ecall_ptr_offsets_len: u64;

    /// First element of the UNIMP handler patch-site offset array.
    pub static sp1_unimp_ptr_offsets: [u64; 0];
    /// Number of entries in [`sp1_unimp_ptr_offsets`].
    pub static sp1_unimp_ptr_offsets_len: u64;

    /// Starting program counter (value of [`crate::CompiledCode::pc_start`]).
    pub static sp1_pc_start: u64;

    /// Base program counter (value of [`crate::CompiledCode::pc_base`]).
    pub static sp1_pc_base: u64;

    /// VM memory region size in bytes (value of [`crate::CompiledCode::memory_size`]).
    pub static sp1_memory_size: u64;
}
