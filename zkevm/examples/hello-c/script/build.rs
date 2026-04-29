//! Build the C guest end-to-end:
//!
//!   1. Use `sp1-build` to build the `libzkevm-cabi` staticlib for
//!      `riscv64im-succinct-zkvm-elf`. sp1-build knows how to invoke
//!      the `succinct` rustc with the right env (RUSTC_BOOTSTRAP=1,
//!      pinned target dir, etc.) — replicating that by hand from a
//!      `Makefile` is fragile.
//!   2. Compile `program/main.c` with clang.
//!   3. Link with `ld.lld` (or rust-lld bundled in the SP1 toolchain).
//!   4. Surface the path to the resulting ELF via the `HELLO_C_ELF` env
//!      var so `src/{execute,prove}.rs` can load it via `include_bytes!`.
//!
//! Tooling assumed on PATH: `clang` (with the riscv64 backend; this
//! ships with stock LLVM/clang 9+). `ld.lld` is preferred on PATH; if
//! absent we look in `~/.sp1/toolchains/*/lib/rustlib/*/bin/gcc-ld/ld.lld`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    // script/ -> hello-c/ -> examples/ -> zkevm/
    let zkevm_root = manifest.parent().unwrap().parent().unwrap().parent().unwrap();
    let cabi_dir = zkevm_root.join("libzkevm-cabi");
    let main_c = zkevm_root.join("examples/hello-c/program/main.c");
    let zkvm_ld = zkevm_root.join("zkvm.ld");
    let include = zkevm_root.join("include");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", main_c.display());
    println!("cargo:rerun-if-changed={}", zkvm_ld.display());
    println!("cargo:rerun-if-changed={}/zkvm_accelerators.h", include.display());
    println!("cargo:rerun-if-changed={}/src/lib.rs", cabi_dir.display());

    // 1) Build libzkevm-cabi for riscv. sp1-build sets RUSTC to the
    //    succinct toolchain's rustc, pins CARGO_TARGET_DIR, etc.
    sp1_build::build_program(cabi_dir.to_str().unwrap());

    let staticlib = cabi_dir
        .join("target")
        .join("elf-compilation")
        .join("riscv64im-succinct-zkvm-elf")
        .join("release")
        .join("libzkevm.a");
    if !staticlib.exists() {
        panic!("expected libzkevm.a at {} after `sp1_build::build_program`", staticlib.display());
    }

    // 2) Compile main.c → main.o via clang.
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
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

    // 3) Link main.o + libzkevm.a → hello.elf via ld.lld.
    let lld = find_lld().expect(
        "ld.lld not found on PATH and no SP1 toolchain has a bundled copy. \
         Install lld (`apt install lld` on Debian/Ubuntu) or run `sp1up`.",
    );
    // `ld.lld` defaults to gnu mode; no `-flavor` needed.
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

    // 4) Surface the ELF path to src/{execute,prove}.rs.
    println!("cargo:rustc-env=HELLO_C_ELF={}", elf.display());
}

/// Look for `ld.lld` first on `PATH`, then under any installed SP1
/// toolchain's bundled `gcc-ld/` directory. The bundled binary is `lld`
/// invoked with `-flavor gnu`, which is `ld.lld`.
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
