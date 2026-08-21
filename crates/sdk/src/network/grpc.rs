use anyhow::{bail, Context, Result};
use std::time::Duration;
use tonic::transport::{ClientTlsConfig, Endpoint, Identity};

/// Configures the endpoint for the gRPC client.
///
/// Sets reasonable settings to handle timeouts and keep-alive.
pub fn configure_endpoint(addr: &str) -> Result<Endpoint> {
    let mut endpoint = Endpoint::new(addr.to_string())?
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .tcp_nodelay(true);

    // Configure TLS if using HTTPS.
    if addr.starts_with("https://") {
        #[cfg(target_os = "ios")]
        let mut tls_config = ClientTlsConfig::new().with_webpki_roots();
        #[cfg(not(target_os = "ios"))]
        let mut tls_config = ClientTlsConfig::new().with_enabled_roots();
        if let Some(identity) = client_identity_from_env()? {
            tls_config = tls_config.identity(identity);
        }
        endpoint = endpoint.tls_config(tls_config)?;
    }

    Ok(endpoint)
}

/// Private networks that require mTLS reject the handshake without a client identity.
fn client_identity_from_env() -> Result<Option<Identity>> {
    let cert_path = std::env::var("NETWORK_MTLS_CERT_PATH").ok().filter(|v| !v.is_empty());
    let key_path = std::env::var("NETWORK_MTLS_KEY_PATH").ok().filter(|v| !v.is_empty());
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read(&cert_path)
                .with_context(|| format!("reading NETWORK_MTLS_CERT_PATH ({cert_path})"))?;
            let key = std::fs::read(&key_path)
                .with_context(|| format!("reading NETWORK_MTLS_KEY_PATH ({key_path})"))?;
            Ok(Some(Identity::from_pem(cert, key)))
        }
        (None, None) => Ok(None),
        _ => bail!(
            "NETWORK_MTLS_CERT_PATH and NETWORK_MTLS_KEY_PATH must be set together; only one is set"
        ),
    }
}
