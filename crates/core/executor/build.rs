pub mod build {
    include!("src/build.rs");
}

fn main() {
    build::detect_executor();
    println!("cargo-if-changed=src/build.rs");
}
