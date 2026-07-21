//! Shared `build.rs` helper for the C example scripts under
//! `zkevm/examples/<name>/script/`.
//!
//! Workflow:
//!   1. `sp1_build::build_program_staticlib` against
//!      `zkevm/libzkevm-cabi/`, producing `libzkevm.a` for
//!      `riscv64im-succinct-zkvm-elf` and returning its path.
//!   2. `clang` (with `sp1_build::CLANG_FLAGS`) compiles the example's
//!      `main.c`.
//!   3. `sp1_build::find_lld()` locates `ld.lld`; we link `main.o` +
//!      `libzkevm.a` against `zkvm/zkvm.ld`.
//!   4. Return the ELF path; the caller surfaces it via
//!      `cargo:rustc-env=GUEST_ELF=...` and the script's
//!      `src/execute.rs` includes it via `include_bytes!(env!(...))`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Build the C example at `<example_dir>/program/main.c` and return
/// the path to the resulting ELF.
///
/// `example_dir` is the directory containing `program/` and `script/`
/// (e.g. `zkevm/examples/hello-c/`).
pub fn build_c_example(example_dir: &Path) -> PathBuf {
    let zkevm_root = example_dir
        .parent()
        .unwrap_or_else(|| panic!("{} has no parent", example_dir.display()))
        .parent()
        .unwrap_or_else(|| panic!("{} has no grandparent", example_dir.display()));
    let cabi_dir = zkevm_root.join("libzkevm-cabi");
    let main_c = example_dir.join("program/main.c");
    let zkvm_ld = zkevm_root.join("zkvm.ld");
    let include = zkevm_root.join("include");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", main_c.display());
    println!("cargo:rerun-if-changed={}", zkvm_ld.display());
    println!("cargo:rerun-if-changed={}/zkvm_accelerators.h", include.display());
    println!("cargo:rerun-if-changed={}/assert.h", include.display());
    println!("cargo:rerun-if-changed={}/src/lib.rs", cabi_dir.display());

    // 1) Build libzkevm-cabi for riscv via sp1-build.
    let staticlib =
        sp1_build::build_program_staticlib(cabi_dir.to_str().expect("cabi path is utf-8"));

    // 2) Compile main.c -> main.o via clang.
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let main_o = out_dir.join("main.o");
    let elf = out_dir.join("hello.elf");

    let status = Command::new("clang")
        .args(sp1_build::CLANG_FLAGS)
        .args(["-O2", "-Wall", "-Wextra"])
        .arg(format!("-I{}", include.display()))
        .arg("-c")
        .arg("-o")
        .arg(&main_o)
        .arg(&main_c)
        .status()
        .expect("failed to spawn `clang`; ensure clang is on PATH");
    if !status.success() {
        panic!("clang failed compiling {} (status: {status})", main_c.display());
    }

    // 3) Link main.o + libzkevm.a -> hello.elf via ld.lld.
    let lld = sp1_build::find_lld().expect(
        "ld.lld not found on PATH and no SP1 toolchain has a bundled copy. \
         Install lld (`apt install lld` on Debian/Ubuntu) or run `sp1up`.",
    );
    let status = Command::new(&lld)
        .arg("-nostdlib")
        .arg("-static")
        .arg(format!("-T{}", zkvm_ld.display()))
        .arg("-o")
        .arg(&elf)
        .arg(&main_o)
        .arg(&staticlib)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn `{}`: {e}", lld.display()));
    if !status.success() {
        panic!("ld.lld failed linking {} (status: {status})", elf.display());
    }

    elf
}
