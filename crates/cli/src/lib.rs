pub mod commands;

use anyhow::{Context, Result};
use reqwest::Client;
use std::process::{Command, Stdio};

pub const RUSTUP_TOOLCHAIN_NAME: &str = "succinct";

/// The latest version (github tag) of the toolchain that is supported by our build system.
///
/// This tag has support for older x86 libc versions (like the one found in Ubuntu 20.04).
/// This tag has support for the recent Macos and ARM targets.
pub const LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG: &str = "succinct-1.88.0";

pub const SP1_VERSION_MESSAGE: &str =
    concat!("sp1", " (", env!("VERGEN_GIT_SHA"), " ", env!("VERGEN_BUILD_TIMESTAMP"), ")");

trait CommandExecutor {
    fn run(&mut self) -> Result<()>;
}

impl CommandExecutor for Command {
    fn run(&mut self) -> Result<()> {
        self.stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .with_context(|| format!("while executing `{:?}`", &self))
            .map(|_| ())
    }
}

pub async fn url_exists(client: &Client, url: &str) -> bool {
    let res = client.head(url).send().await;
    res.is_ok()
}

#[allow(unreachable_code)]
pub fn is_supported_target() -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return true;

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    return true;

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return true;

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return true;

    false
}

pub fn get_target() -> String {
    let mut target: target_lexicon::Triple = target_lexicon::HOST;

    // We don't want to operate on the musl toolchain, even if the CLI was compiled with musl
    if target.environment == target_lexicon::Environment::Musl {
        target.environment = target_lexicon::Environment::Gnu;
    }

    target.to_string()
}

pub async fn get_toolchain_download_url(client: &Client, target: String) -> String {
    let all_releases = client
        .get("https://api.github.com/repos/succinctlabs/rust/releases")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    // Check if the release exists.
    let _ = all_releases
        .as_array()
        .expect("Failed to fetch releases list")
        .iter()
        .find(|release| {
            release["tag_name"].as_str().unwrap() == LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG
        })
        .unwrap_or_else(|| {
            panic!(
                "No release found for the expected tag: {LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG}",
            );
        });

    let url = format!(
        "https://github.com/succinctlabs/rust/releases/download/{LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG}/rust-toolchain-{target}.tar.gz"
    );

    url
}
