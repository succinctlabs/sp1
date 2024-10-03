use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs { output_directory: "fibonacci/program/elf".into(), ..Default::default() },
    );
}
