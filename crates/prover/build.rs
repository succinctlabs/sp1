use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use sha2::{Digest, Sha256};

const FILENAME: &str = "vk_map.bin";
const SRC_PATH: &str = "src/vk_map.bin";
const SHA256_HASH: &str = "5e735f6e44f56e9eee91e5626252663afcc5263287d1c5980367b3f9f930a0e8";

fn check_sha2(path: &Path) -> bool {
    let data = fs::read(path).unwrap();

    hex::encode(Sha256::digest(data)) == SHA256_HASH
}

fn main() {
    println!("cargo:rerun-if-env-changed=VK_MAP_SRC_PATH");

    let src_path = SRC_PATH.to_string();
    let src_path = PathBuf::from_str(src_path.as_str()).unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let out_path = out_dir.join(FILENAME);

    if env::var("DOCS_RS").is_ok() && !out_path.exists() {
        eprintln!("Writing empty file to {}", out_path.display());
        fs::write(&out_path, b"").unwrap();
        return;
    }

    if out_path.exists() {
        eprintln!("Checking SHA256 of {}", out_path.display());
        if check_sha2(&out_path) {
            eprintln!("SHA256 check passed");
            return;
        }
        eprintln!("SHA256 check failed, removing file");
        fs::remove_file(&out_path).unwrap();
    }

    if src_path.exists() && check_sha2(&src_path) {
        eprintln!("Copying file from {} to {}", src_path.display(), out_path.display());
        fs::copy(&src_path, &out_path).unwrap();
        return;
    }

    let url = "https://sp1-circuits.s3.us-east-2.amazonaws.com/vk-map-v5.0.0";
    eprintln!("Downloading {url}");

    let client = reqwest::blocking::Client::builder().use_rustls_tls().build().unwrap();

    let response = client.get(url).send().unwrap();
    if !response.status().is_success() {
        panic!("Failed to download file: HTTP {}", response.status());
    }

    let bytes = response.bytes().unwrap();

    let computed_hash = hex::encode(Sha256::digest(&bytes));
    if computed_hash != SHA256_HASH {
        panic!("SHA256 mismatch: expected {}, got {}", SHA256_HASH, computed_hash);
    }

    let mut file = fs::File::create(&out_path).unwrap();
    file.write_all(&bytes).unwrap();

    eprintln!("Successfully downloaded and verified {} ({} bytes)", FILENAME, bytes.len());
}
