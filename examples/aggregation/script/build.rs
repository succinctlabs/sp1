fn main() {
    sp1_helper::build_program(&format!("{}/../program", env!("CARGO_MANIFEST_DIR")));
    sp1_helper::build_program(&format!(
        "{}/../../fibonacci/program",
        env!("CARGO_MANIFEST_DIR")
    ));
}
