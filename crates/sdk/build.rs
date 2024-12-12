fn main() {
    vergen::EmitBuilder::builder().build_timestamp().git_sha(true).emit().unwrap();

    if matches!(std::env::var("OPT_LEVEL").unwrap().as_str(), "0" | "1") {
        println!("cargo:rustc-env=SP1_OPT_LEVEL_IS_LOW=1");
    }
}
