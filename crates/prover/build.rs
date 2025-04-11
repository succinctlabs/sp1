use std::{
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use downloader::{verify, Download, DownloadSummary, Downloader};
use sha2::{Digest, Sha256};

const FILENAME: &str = "vk_map.bin";
const SRC_PATH: &str = "src/vk_map.bin";
const SHA256_HASH: &str = "5791e67cb339f4936f21f0e7aa40fea6e534b4284175285444935613f7d61827";

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

    let mut downloader = Downloader::builder().download_folder(out_dir).build().unwrap();
    let url = "https://sp1-circuits.s3.us-east-2.amazonaws.com/vk-map-v4.0.0-rc.3".to_string();
    eprintln!("Downloading {url}");
    let dl = Download::new(&url)
        .file_name(&PathBuf::from_str(FILENAME).unwrap())
        .verify(verify::with_digest::<Sha256>(hex::decode(SHA256_HASH).unwrap()));
    let results = downloader.download(&[dl]).unwrap();
    for result in results {
        let summary: DownloadSummary = result.unwrap();
        eprintln!("{summary}");
    }
}
