use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs { output_directory: "json/program/elf".into(), ..Default::default() },
    );
}
