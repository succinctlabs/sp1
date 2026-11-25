use sp1_build::BuildArgs;

fn main() {
    println!("cargo:rerun-if-changed=program/xof_cases.rs");
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-9-9".to_string()], ..Default::default() },
    );
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-10-6".to_string()], ..Default::default() },
    );
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-10-8".to_string()], ..Default::default() },
    );
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-10-9".to_string()], ..Default::default() },
    );
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-11-0".to_string()], ..Default::default() },
    );
}
