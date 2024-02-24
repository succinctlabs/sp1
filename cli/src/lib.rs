mod build;
pub mod commands;
mod util;

use anyhow::Result;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::cmp::min;
use std::fs::File as SyncFile;
use std::io::Write;
use std::process::{Command, Stdio};

pub const RUSTUP_TOOLCHAIN_NAME: &str = "succinct";

trait CommandExecutor {
    fn run(&mut self) -> Result<()>;
}

impl CommandExecutor for Command {
    fn run(&mut self) -> Result<()> {
        self.stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        Ok(())
    }
}

#[allow(clippy::useless_format)]
pub async fn download_file(client: &Client, url: &str, path: &str) -> Result<(), String> {
    let res = client
        .get(url)
        .send()
        .await
        .or(Err(format!("Failed to GET from '{}'", &url)))?;
    let total_size = res
        .content_length()
        .ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));
    pb.set_message(&format!("Downloading {}", url));

    let mut file = SyncFile::create(path).or(Err(format!("Failed to create file '{}'", path)))?;
    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.or(Err(format!("Error while downloading file")))?;
        file.write_all(&chunk)
            .or(Err(format!("Error while writing to file")))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }

    pb.finish_with_message(&format!("Downloaded {} to {}", url, path));
    Ok(())
}

pub fn get_target() -> String {
    target_lexicon::HOST.to_string()
}

#[allow(unreachable_code)]
pub fn get_toolchain_download_url() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return "https://pub-e4d9616fb885415597ff4c4d2b476ffb.r2.dev/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz";

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    return "https://pub-e4d9616fb885415597ff4c4d2b476ffb.r2.dev/rust-toolchain-aarch64-unknown-linux-gnu.tar.gz";

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return "https://pub-e4d9616fb885415597ff4c4d2b476ffb.r2.dev/rust-toolchain-aarch64-apple-darwin.tar.gz";

    panic!("Unsupported architecture. Please build the toolchain from source.")
}
