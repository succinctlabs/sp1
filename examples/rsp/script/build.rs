use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        &format!("../{}", "program"),
        BuildArgs { ignore_rust_version: true, ..Default::default() },
    );
}
