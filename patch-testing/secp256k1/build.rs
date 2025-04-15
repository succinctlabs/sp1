use sp1_build::BuildArgs;

fn main() {
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-29-1".to_string()], ..Default::default() },
    );
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-30-0".to_string()], ..Default::default() },
    );
}
