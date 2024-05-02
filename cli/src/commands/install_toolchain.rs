use anyhow::Result;
use clap::Parser;
use dirs::home_dir;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;
use sp1_sdk::artifacts::download_file;
use std::fs::{self};
use std::io::Read;
use std::process::Command;

#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;

use crate::{get_target, get_toolchain_download_url, url_exists, RUSTUP_TOOLCHAIN_NAME};

#[derive(Parser)]
#[command(
    name = "install-toolchain",
    about = "Install the cargo-prove toolchain."
)]
pub struct InstallToolchainCmd {}

impl InstallToolchainCmd {
    pub fn run(&self) -> Result<()> {
        // Setup client.
        let client = Client::builder().user_agent("Mozilla/5.0").build()?;

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
                                println!("Failed to remove directory {:?}: {}", entry_path, err);
                            }
                        } else if entry_path.is_file() {
                            if let Err(err) = fs::remove_file(&entry_path) {
                                println!("Failed to remove file {:?}: {}", entry_path, err);
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
            Err(err) => println!("Failed to create ~/.sp1 directory: {}", err),
        };
        let target = get_target();
        let toolchain_asset_name = format!("rust-toolchain-{}.tar.gz", target);
        let toolchain_archive_path = root_dir.join(toolchain_asset_name.clone());
        let toolchain_dir = root_dir.join(&target);
        let rt = tokio::runtime::Runtime::new()?;

        let toolchain_download_url =
            rt.block_on(get_toolchain_download_url(&client, target.to_string()));

        let artifact_exists = rt.block_on(url_exists(&client, toolchain_download_url.as_str()));
        if !artifact_exists {
            return Err(anyhow::anyhow!(
                "Unsupported architecture. Please build the toolchain from source."
            ));
        }

        // Download the toolchain.
        let mut file = fs::File::create(toolchain_archive_path)?;
        rt.block_on(download_file(
            &client,
            toolchain_download_url.as_str(),
            &mut file,
        ))
        .unwrap();

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
            .args([
                "-xzf",
                &toolchain_asset_name,
                "-C",
                &toolchain_dir.to_string_lossy(),
            ])
            .status()?;

        // Move the toolchain to a randomly named directory in the 'toolchains' folder
        let toolchains_dir = root_dir.join("toolchains");
        fs::create_dir_all(&toolchains_dir)?;
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
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
        let rustlib_bin_dir = new_toolchain_dir.join(format!("lib/rustlib/{}/bin", target));
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
