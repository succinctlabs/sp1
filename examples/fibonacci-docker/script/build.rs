fn main() {
    sp1_build::build_program_with_args(
        &format!("{}/../program", env!("CARGO_MANIFEST_DIR")),
        sp1_build::BuildArgs {
            docker: true,
            ..Default::default()
        },
    );
}
