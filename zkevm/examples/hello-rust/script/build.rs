//! Build the sibling `program/` guest into an SP1-ready ELF and surface
//! its path via `include_elf!("hello-rust")`.
//!
//! `sp1-build` runs `cargo build --release --target riscv64im-succinct-zkvm-elf`
//! using the SP1 succinct toolchain. It honors the `program/` workspace's
//! own `panic = "abort"` profile and `.cargo/config.toml`, so we don't
//! need to set anything special here.

fn main() {
    sp1_build::build_program("../program");
}
