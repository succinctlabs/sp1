fn main() {
    println!("cargo::rustc-check-cfg=cfg(sp1_ci_in_progress)");
    if std::env::var("SP1_CI_IN_PROGRESS").is_ok() {
        println!("cargo::rustc-cfg=sp1_ci_in_progress");
    }
}
