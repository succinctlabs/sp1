fn main() {
    #[cfg(debug_assertions)]
    compile_error!(
        "sp1-sdk must be used in release mode. Please compile with the --release flag."
    );

    vergen::EmitBuilder::builder().build_timestamp().git_sha(true).emit().unwrap();
}
