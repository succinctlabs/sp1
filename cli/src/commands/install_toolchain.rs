use anyhow::Result;
use clap::Parser;
use dirs::home_dir;
use flate2::read::GzDecoder;
use reqwest::Client;
use std::fs::{self, File};
use std::process::Command;
use tar::Archive;

use crate::{
    download_file, get_target, get_toolchain_download_url, CommandExecutor, RUSTUP_TOOLCHAIN_NAME,
};

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
        let client = Client::builder().user_agent("Mozilla/5.0").build()?;

        // Setup variables.
        let root_dir = home_dir().unwrap().join(".cargo-prove");
        fs::create_dir_all(&root_dir)?;
        let target = get_target();
        let toolchain_asset_name = format!("rust-toolchain-{}.tar.gz", target);
        let toolchain_archive_path = root_dir.join(toolchain_asset_name.clone());
        let toolchain_dir = root_dir.join(target);
        let toolchain_download_url = get_toolchain_download_url();

        // Download the toolchain.
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(download_file(
            &client,
            toolchain_download_url,
            toolchain_archive_path.to_str().unwrap(),
        ))
        .unwrap();

        // Unpack the toolchain.
        let tar_gz = File::open(&toolchain_archive_path)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(&toolchain_dir)?;
        fs::remove_file(&toolchain_archive_path)?;

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

        Ok(())
    }
}
