use std::{cmp::min, io::Write, path::PathBuf, process::Command};

use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;

use crate::utils::block_on;

/// The base URL for the S3 bucket containing the groth16 artifacts.
pub const GROTH16_ARTIFACTS_URL_BASE: &str = "https://sp1-circuits.s3-us-east-2.amazonaws.com";

/// The current version of the groth16 artifacts.
pub const GROTH16_ARTIFACTS_COMMIT: &str = "9f43e920";

/// Install the latest groth16 artifacts.
///
/// This function will download the latest groth16 artifacts from the S3 bucket and extract them to
/// the directory specified by [groth16_artifacts_dir()].
pub fn install_groth16_artifacts(build_dir: PathBuf) {
    // Create the build directory.
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");

    // Download the artifacts.
    let download_url = format!(
        "{}/{}.tar.gz",
        GROTH16_ARTIFACTS_URL_BASE, GROTH16_ARTIFACTS_COMMIT
    );
    let mut artifacts_tar_gz_file =
        tempfile::NamedTempFile::new().expect("failed to create tempfile");
    let client = Client::builder()
        .build()
        .expect("failed to create reqwest client");
    block_on(download_file(
        &client,
        &download_url,
        &mut artifacts_tar_gz_file,
    ))
    .expect("failed to download file");

    // Extract the tarball to the build directory.
    let mut res = Command::new("tar")
        .args([
            "-Pxzf",
            artifacts_tar_gz_file.path().to_str().unwrap(),
            "-C",
            build_dir.to_str().unwrap(),
        ])
        .spawn()
        .expect("failed to extract tarball");
    res.wait().unwrap();

    println!(
        "[sp1] downloaded {} to {:?}",
        download_url,
        build_dir.to_str().unwrap(),
    );
}

/// The directory where the groth16 artifacts will be stored based on [GROTH16_ARTIFACTS_VERSION]
/// and [GROTH16_ARTIFACTS_URL_BASE].
pub fn install_groth16_artifacts_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap()
        .join(".sp1")
        .join("circuits")
        .join(GROTH16_ARTIFACTS_COMMIT)
}

/// Download the file with a progress bar that indicates the progress.
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut tempfile::NamedTempFile,
) -> std::result::Result<(), String> {
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
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk)
            .or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}
