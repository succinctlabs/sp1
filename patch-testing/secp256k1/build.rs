use sp1_build::BuildArgs;

fn main() {
    sp1_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-29-1".to_string()], ..Default::default() },
    );
    // TODO: Find a solution to avoid conflics on secp256k1-sys
    //sp1_build::build_program_with_args(
    //    "./program",
    //    BuildArgs { features: vec!["v0-30-0".to_string()], ..Default::default() },
    //);
}
