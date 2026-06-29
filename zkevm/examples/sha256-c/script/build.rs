fn main() {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let example_dir = manifest.parent().unwrap();
    let elf = zkevm_c_build::build_c_example(example_dir);
    println!("cargo:rustc-env=SHA256_C_ELF={}", elf.display());
}
