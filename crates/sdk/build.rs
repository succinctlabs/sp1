fn main() {
    vergen::EmitBuilder::builder().build_timestamp().git_sha(true).emit().unwrap();

    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_else(|_| "0".to_string());
    if opt_level == "0" || opt_level == "1" {
        println!("cargo:rustc-env=SP1_OPT_LEVEL_IS_LOW=1");
    }
}
