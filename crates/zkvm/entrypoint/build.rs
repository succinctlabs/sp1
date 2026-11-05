use std::fs::write;
use std::path::Path;
use std::{env, option_env};

fn main() {
    println!("cargo:rerun-if-env-changed=SP1_ZKVM_MAX_MEMORY");
    println!("cargo:rerun-if-env-changed=SP1_ZKVM_INPUT_REGION_SIZE");

    let max_memory: u64 = if let Some(s) = option_env!("SP1_ZKVM_MAX_MEMORY") {
        s.parse().expect("SP1_ZKVM_MAX_MEMORY must be a valid integer!")
    } else {
        1 << 37
    };
    assert!(max_memory <= 1u64 << 48, "SP1_ZKVM_MAX_MEMORY must not exceed 2^48");

    let input_region_size: u64 = if let Some(s) = option_env!("SP1_ZKVM_INPUT_REGION_SIZE") {
        s.parse().expect("SP1_ZKVM_INPUT_REGION_SIZE must be a valid integer!")
    } else {
        1 << 34
    };

    let source = format!(
        r#"
#[allow(dead_code)]
mod configs {{
    pub const MAX_MEMORY: usize = {max_memory};
    pub const INPUT_REGION_SIZE: usize = {input_region_size};
}}
"#
    );

    let out_dir = env::var("OUT_DIR").unwrap();
    let source_path = Path::new(&out_dir).join("configs.rs");
    write(source_path, source).expect("write");
}
