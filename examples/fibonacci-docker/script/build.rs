fn main() {
    sp1_helper::build_program_with_args(
        &format!("{}/../program", env!("CARGO_MANIFEST_DIR")),
        sp1_helper::BuildArgs {
            docker: true,
            ..Default::default()
        },
    );
}
