fn main() {
    println!("cargo:rerun-if-changed=program/residue_cases.rs");
    sp1_build::build_program("./program");
}
