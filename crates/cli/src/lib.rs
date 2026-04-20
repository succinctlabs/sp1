pub mod commands;

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use tokio::time::sleep;

pub const RUSTUP_TOOLCHAIN_NAME: &str = "succinct";

/// The latest version (github tag) of the toolchain that is supported by our build system.
pub const LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG: &str = "succinct-1.93.0-64bit";

pub const SP1_VERSION_MESSAGE: &str =
    concat!("sp1", " (", env!("VERGEN_GIT_SHA"), " ", env!("VERGEN_BUILD_TIMESTAMP"), ")");

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_SECS: u64 = 2;

/// Send an HTTP request with retries and exponential backoff.
///
/// Retries on network errors and non-success HTTP status codes, up to `MAX_RETRIES` times
/// with exponential backoff starting at `INITIAL_BACKOFF_SECS`.
pub(crate) async fn send_with_retry(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    headers: Option<reqwest::header::HeaderMap>,
    operation: &str,
) -> Result<reqwest::Response> {
    let mut last_err = None;
    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let backoff = Duration::from_secs(INITIAL_BACKOFF_SECS << (attempt - 1));
            eprintln!(
                "{operation} failed, retrying in {}s (attempt {}/{})...",
                backoff.as_secs(),
                attempt + 1,
                MAX_RETRIES + 1
            );
            sleep(backoff).await;
        }
        let mut request = client.request(method.clone(), url);
        if let Some(ref headers) = headers {
            request = request.headers(headers.clone());
        }
        match request.send().await {
            Ok(res) if res.status().is_success() => return Ok(res),
            Ok(res) => {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                last_err = Some(format!("HTTP {status}: {body}"));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
    }
    anyhow::bail!(
        "{operation} failed after {} attempts: {}",
        MAX_RETRIES + 1,
        last_err.unwrap_or_default()
    )
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

/// Find the toolchain asset for the given target in the GitHub releases API and return
/// its API download URL. Using the API URL (with `Accept: application/octet-stream`)
/// instead of the browser download URL ensures authentication works correctly, including
/// for draft releases.
pub async fn get_toolchain_asset_url(client: &Client, target: String) -> Result<String> {
    let response = send_with_retry(
        client,
        reqwest::Method::GET,
        "https://api.github.com/repos/succinctlabs/rust/releases",
        None,
        "Fetching GitHub releases",
    )
    .await?;

    let all_releases: serde_json::Value =
        response.json().await.context("Failed to parse releases response")?;

    let releases = all_releases.as_array().context("GitHub API response was not a JSON array")?;

    let release = releases
        .iter()
        .find(|release| {
            release["tag_name"].as_str() == Some(LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG)
        })
        .with_context(|| {
            format!("No release found for tag: {LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG}")
        })?;

    let expected_name = format!("rust-toolchain-{target}.tar.gz");
    let assets = release["assets"].as_array().context("Release has no assets array")?;
    let asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&expected_name))
        .with_context(|| {
            format!("No asset '{expected_name}' found in release {LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG}")
        })?;

    asset["url"].as_str().map(String::from).context("Asset has no API URL")
}
