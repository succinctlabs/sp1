use anyhow::{anyhow, Result};
use clap::Parser;
use dirs::home_dir;
use flate2::read::GzDecoder;
use reqwest::{header::HeaderMap, Client};
use serde::Deserialize;
use std::{
    fs::{self, File as SyncFile},
    process::Command,
};
use tar::Archive;

use crate::{download_file, CommandExecutor, RUSTUP_TOOLCHAIN_NAME};

#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser)]
#[command(
    name = "install-toolchain",
    about = "Install the cargo-prove toolchain."
)]
pub struct InstallToolchainCmd {}

impl InstallToolchainCmd {
    pub fn run(&self) -> Result<()> {
        // Setup client.
        let mut headers = HeaderMap::new();
        match std::env::var("GITHUB_ACCESS_TOKEN") {
            Ok(github_access_token) => {
                headers.insert(
                    "Authorization",
                    format!("Bearer {}", github_access_token).parse()?,
                );
                println!("GITHUB_ACCESS_TOKEN found. Using authenticated requests.")
            }
            Err(_) => {
                panic!("Not GITHUB_ACCESS_TOKEN found. Please set one.")
            }
        };
        let client = Client::builder()
            .default_headers(headers)
            .user_agent("Mozilla/5.0")
            .build()?;

        // Setup variables.
        let root_dir = home_dir().unwrap().join(".cargo-prove");
        let target = get_target();
        let toolchain_asset_name = format!("rust-toolchain-{}.tar.gz", target);
        let toolchain_archive_path = root_dir.join(toolchain_asset_name.clone());
        let toolchain_dir = root_dir.join(target);
        let rt = tokio::runtime::Runtime::new()?;
        let toolchain_download_url = rt.block_on(get_toolchain_download_url(
            &client,
            &toolchain_asset_name.clone(),
        ))?;

        // Download the toolchain.
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(download_file(
            &client,
            &toolchain_download_url,
            toolchain_archive_path.to_str().unwrap(),
        ))
        .unwrap();

        // Unpack the toolchain.
        let tar_gz = SyncFile::open(&toolchain_archive_path)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(&toolchain_dir)?;

        // Remove the existing toolchain from rustup, if it exists.
        match Command::new("rustup")
            .args(["toolchain", "remove", RUSTUP_TOOLCHAIN_NAME])
            .run()
        {
            Ok(_) => println!("Succesfully removed existing toolchain."),
            Err(_) => println!("No existing toolchain to remove."),
        }

        // Link the toolchain to rustup.
        Command::new("rustup")
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(&toolchain_dir)
            .run()?;
        println!("Succesfully linked toolchain to rustup.");

        // Ensure permissions.
        #[cfg(target_family = "unix")]
        {
            let bin_dir = toolchain_dir.join("bin");
            let rustlib_bin_dir = toolchain_dir.join(format!("lib/rustlib/{target}/bin"));
            for wrapped_entry in fs::read_dir(bin_dir)?.chain(fs::read_dir(rustlib_bin_dir)?) {
                let entry = wrapped_entry?;
                if entry.file_type()?.is_file() {
                    let mut perms = entry.metadata()?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(entry.path(), perms)?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize)]
struct GithubReleaseData {
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    id: u64,
}

async fn get_toolchain_download_url(client: &Client, asset_name: &str) -> Result<String> {
    let tag = "v2024-01-24.6";
    let release_url = format!(
        "https://api.github.com/repos/succinctlabs/rust/releases/tags/{}",
        tag
    );
    let data: GithubReleaseData = client.get(&release_url).send().await?.json().await?;
    for asset in data.assets {
        if asset.name == asset_name {
            let download_url = format!(
                "https://api.github.com/repos/succinctlabs/rust/releases/assets/{}",
                asset.id
            );
            return Ok(download_url);
        }
    }

    Err(anyhow!("Asset not found."))
}

#[allow(unreachable_code)]
fn get_target() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return "x86_64-unknown-linux-gnu";

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return "x86_64-apple-darwin";

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return "aarch64-apple-darwin";

    panic!("Unsupported architecture. Please build the toolchain from source.")
}
