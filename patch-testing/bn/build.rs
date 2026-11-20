fn main() {
    println!("cargo:rerun-if-changed=program/affine_conversions.rs");
    println!("cargo:rerun-if-changed=program/g2_validation.rs");
    sp1_build::build_program("./program");
}
