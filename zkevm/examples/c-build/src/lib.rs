//! Shared `build.rs` helper for the C example scripts under
//! `zkevm/examples/<name>/script/`.
//!
//! Workflow:
//!   1. `sp1_build::build_program` against `zkevm/libzkevm-cabi/`,
//!      which produces `libzkevm.a` for `riscv64im-succinct-zkvm-elf`.
//!      sp1-build sets RUSTC to the succinct toolchain, pins
//!      `CARGO_TARGET_DIR`, sets the right rustflags, etc.
//!   2. `clang --target=riscv64-unknown-none-elf` compiles the
//!      example's `main.c` to `main.o`.
//!   3. `ld.lld` links `main.o` + `libzkevm.a` against `zkvm/zkvm.ld`
//!      into `hello.elf`.
//!   4. Return the ELF path; the caller does
//!      `println!("cargo:rustc-env=GUEST_ELF={}", elf.display());`
//!      and the script's `src/execute.rs` consumes it via
//!      `include_bytes!(env!("GUEST_ELF"))`.
//!
//! Tooling: `clang` (with the riscv64 backend; ships with stock
//! LLVM/clang 9+). `ld.lld` is preferred on PATH; if absent we look
//! under `~/.sp1/toolchains/*/lib/rustlib/*/bin/gcc-ld/ld.lld`
//! (the bundled SP1 toolchain has it).

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
    println!("cargo:rerun-if-changed={}/src/lib.rs", cabi_dir.display());

    // 1) Build libzkevm-cabi for riscv. sp1-build sets up the succinct
    //    toolchain env (RUSTC path, target dir, rustflags).
    sp1_build::build_program(cabi_dir.to_str().expect("cabi path is utf-8"));

    let staticlib = cabi_dir
        .join("target")
        .join("elf-compilation")
        .join("riscv64im-succinct-zkvm-elf")
        .join("release")
        .join("libzkevm.a");
    if !staticlib.exists() {
        panic!("expected libzkevm.a at {} after `sp1_build::build_program`", staticlib.display());
    }

    // 2) Compile main.c -> main.o via clang.
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let main_o = out_dir.join("main.o");
    let elf = out_dir.join("hello.elf");

    let status = Command::new("clang")
        .args([
            "--target=riscv64-unknown-none-elf",
            "-march=rv64im",
            "-mabi=lp64",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-nostdlibinc",
            "-O2",
            "-Wall",
            "-Wextra",
        ])
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
    let lld = find_lld().expect(
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

/// Look for `ld.lld` first on `PATH`, then under any installed SP1
/// toolchain's bundled `gcc-ld/` directory.
fn find_lld() -> Option<PathBuf> {
    if Command::new("ld.lld").arg("--version").output().is_ok_and(|o| o.status.success()) {
        return Some(PathBuf::from("ld.lld"));
    }

    let home = std::env::var_os("HOME")?;
    let toolchains = Path::new(&home).join(".sp1/toolchains");
    for entry in std::fs::read_dir(&toolchains).ok()?.flatten() {
        let candidate = entry.path().join("lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
