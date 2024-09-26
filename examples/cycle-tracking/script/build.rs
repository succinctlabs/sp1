use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args("../program", BuildArgs {
        binary: "normal".to_string(),
        ..Default::default()
    });
    build_program_with_args("../program", BuildArgs {
        binary: "report".to_string(),
        ..Default::default()
    });
}
