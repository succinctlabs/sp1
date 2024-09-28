use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs { output_directory: "bls12381/program/elf".into(), ..Default::default() },
    );
}
