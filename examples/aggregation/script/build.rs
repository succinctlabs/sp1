fn main() {
    sp1_helper::build_program(&format!(
        "{}/../programs/aggregation",
        env!("CARGO_MANIFEST_DIR")
    ));
    sp1_helper::build_program(&format!(
        "{}/../programs/fibonacci",
        env!("CARGO_MANIFEST_DIR")
    ));
}
