//! Internal SDK build helper.
//!
//! Drives `sp1_build::build_program_staticlib` against
//! `zkevm/libzkevm-cabi/` (which `cargo build` from a Makefile can't
//! easily do, because the succinct toolchain has no standalone `cargo`
//! binary and the rustup-proxy fallback paths look for a `rust-src`
//! component that isn't shipped). Then copies `libzkevm.a` plus the
//! linker script and headers into `zkevm/sdk/`.

use std::path::PathBuf;

#[allow(clippy::print_stdout)]
fn main() {
    let zkevm_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("build-sdk crate has no parent")
        .to_path_buf();
    let cabi_dir = zkevm_root.join("libzkevm-cabi");

    let staticlib =
        sp1_build::build_program_staticlib(cabi_dir.to_str().expect("cabi path is utf-8"));

    let sdk_dir = zkevm_root.join("sdk");
    let include_dst = sdk_dir.join("include");
    std::fs::create_dir_all(&include_dst).expect("create sdk/include");

    let dst_lib = sdk_dir.join("libzkevm.a");
    let dst_ld = sdk_dir.join("zkvm.ld");
    let dst_hdr = include_dst.join("zkvm_accelerators.h");

    std::fs::copy(&staticlib, &dst_lib)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", staticlib.display(), dst_lib.display()));
    std::fs::copy(zkevm_root.join("zkvm.ld"), &dst_ld).expect("copy zkvm.ld");
    std::fs::copy(zkevm_root.join("include/zkvm_accelerators.h"), &dst_hdr)
        .expect("copy zkvm_accelerators.h");

    println!("wrote sdk/ at {}", sdk_dir.display());
    println!("  {}", dst_lib.display());
    println!("  {}", dst_ld.display());
    println!("  {}", dst_hdr.display());
}
