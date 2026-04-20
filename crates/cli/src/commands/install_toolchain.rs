use std::{
    fs::{self},
    io::Read,
    process::Command,
};

use anyhow::Result;
use clap::Parser;
use dirs::home_dir;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;

#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;

use crate::{
    get_target, get_toolchain_asset_url, is_supported_target, send_with_retry,
    RUSTUP_TOOLCHAIN_NAME,
};

#[derive(Parser)]
#[command(name = "install-toolchain", about = "Install the cargo-prove toolchain.")]
pub struct InstallToolchainCmd {
    #[arg(short, long, env = "GITHUB_TOKEN")]
    pub token: Option<String>,
}

impl InstallToolchainCmd {
    #[allow(clippy::uninlined_format_args)]
    pub async fn run(&self) -> Result<()> {
        // Check if rust is installed.
        if Command::new("rustup")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return Err(anyhow::anyhow!(
                "Rust is not installed. Please install Rust from https://rustup.rs/ and try again."
            ));
        }

        // Setup client with optional token.
        let client_builder = Client::builder().user_agent("Mozilla/5.0");
        let client = if let Some(ref token) = self.token {
            client_builder
                .default_headers({
                    let mut headers = reqwest::header::HeaderMap::new();
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        reqwest::header::HeaderValue::from_str(&format!("token {token}")).unwrap(),
                    );
                    headers
                })
                .build()?
        } else {
            client_builder.build()?
        };

        // Setup variables.
        let root_dir = home_dir().unwrap().join(".sp1");
        match fs::read_dir(&root_dir) {
            Ok(entries) =>
            {
                #[allow(clippy::manual_flatten)]
                for entry in entries {
                    if let Ok(entry) = entry {
                        let entry_path = entry.path();
                        let entry_name = entry_path.file_name().unwrap();
                        if entry_path.is_dir()
                            && entry_name != "bin"
                            && entry_name != "circuits"
                            && entry_name != "toolchains"
                        {
                            if let Err(err) = fs::remove_dir_all(&entry_path) {
                                println!("Failed to remove directory {entry_path:?}: {err}");
                            }
                        } else if entry_path.is_file() {
                            if let Err(err) = fs::remove_file(&entry_path) {
                                println!("Failed to remove file {entry_path:?}: {err}");
                            }
                        }
                    }
                }
            }
            Err(_) => println!("No existing ~/.sp1 directory to remove."),
        }
        println!("Successfully cleaned up ~/.sp1 directory.");
        match fs::create_dir_all(&root_dir) {
            Ok(_) => println!("Successfully created ~/.sp1 directory."),
            Err(err) => println!("Failed to create ~/.sp1 directory: {err}"),
        };

        assert!(
            is_supported_target(),
            "Unsupported architecture. Please build the toolchain from source."
        );
        let target = get_target();
        let toolchain_asset_name = format!("rust-toolchain-{target}.tar.gz");
        let toolchain_archive_path = root_dir.join(toolchain_asset_name.clone());
        let toolchain_dir = root_dir.join(&target);

        let toolchain_asset_url = get_toolchain_asset_url(&client, target.to_string()).await?;

        // Download the toolchain via the GitHub API. Using the API asset URL with
        // Accept: application/octet-stream works correctly with authentication,
        // unlike browser download URLs which redirect to a CDN that rejects the
        // Authorization header.
        let mut file = tokio::fs::File::create(toolchain_archive_path).await.unwrap();
        download_file(&client, toolchain_asset_url.as_str(), &mut file)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        // Remove the existing toolchain from rustup, if it exists.
        let mut child = Command::new("rustup")
            .current_dir(&root_dir)
            .args(["toolchain", "remove", RUSTUP_TOOLCHAIN_NAME])
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let res = child.wait();
        match res {
            Ok(_) => {
                let mut stdout = child.stdout.take().unwrap();
                let mut content = String::new();
                stdout.read_to_string(&mut content).unwrap();
                if !content.contains("no toolchain installed") {
                    println!("Successfully removed existing toolchain.");
                }
            }
            Err(_) => println!("Failed to remove existing toolchain."),
        }

        // Unpack the toolchain.
        fs::create_dir_all(toolchain_dir.clone())?;
        Command::new("tar")
            .current_dir(&root_dir)
            .args(["-xzf", &toolchain_asset_name, "-C", &toolchain_dir.to_string_lossy()])
            .status()?;

        // Move the toolchain to a randomly named directory in the 'toolchains' folder
        let toolchains_dir = root_dir.join("toolchains");
        fs::create_dir_all(&toolchains_dir)?;
        let random_string: String =
            rand::thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        let new_toolchain_dir = toolchains_dir.join(random_string);
        fs::rename(&toolchain_dir, &new_toolchain_dir)?;

        // Link the new toolchain directory to rustup
        Command::new("rustup")
            .current_dir(&root_dir)
            .args([
                "toolchain",
                "link",
                RUSTUP_TOOLCHAIN_NAME,
                &new_toolchain_dir.to_string_lossy(),
            ])
            .status()?;
        println!("Successfully linked toolchain to rustup.");

        // Ensure permissions.
        let bin_dir = new_toolchain_dir.join("bin");
        let rustlib_bin_dir = new_toolchain_dir.join(format!("lib/rustlib/{target}/bin"));
        for entry in fs::read_dir(bin_dir)?.chain(fs::read_dir(rustlib_bin_dir)?) {
            let entry = entry?;
            if entry.path().is_file() {
                let mut perms = entry.metadata()?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(entry.path(), perms)?;
            }
        }

        Ok(())
    }
}

pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> std::result::Result<(), String> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::ACCEPT, "application/octet-stream".parse().unwrap());
    let res = send_with_retry(client, reqwest::Method::GET, url, Some(headers), "Download")
        .await
        .map_err(|e| e.to_string())?;

    let total_size =
        res.content_length().ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk).await.or(Err("Error while writing to file"))?;
        let new = (downloaded + (chunk.len() as u64)).min(total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}
