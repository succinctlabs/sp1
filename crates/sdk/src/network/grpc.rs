use std::time::Duration;
use tonic::transport::{ClientTlsConfig, Endpoint, Error};

/// Configures the endpoint for the gRPC client.
///
/// Sets reasonable settings to handle timeouts and keep-alive.
pub fn configure_endpoint(addr: &str) -> Result<Endpoint, Error> {
    let mut endpoint = Endpoint::new(addr.to_string())?
        .timeout(Duration::from_mins(1))
        .connect_timeout(Duration::from_secs(15))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_mins(1)))
        .tcp_nodelay(true);

    // Configure TLS if using HTTPS.
    if addr.starts_with("https://") {
        #[cfg(target_os = "ios")]
        let tls_config = ClientTlsConfig::new().with_webpki_roots();
        #[cfg(not(target_os = "ios"))]
        let tls_config = ClientTlsConfig::new().with_enabled_roots();
        endpoint = endpoint.tls_config(tls_config)?;
    }

    Ok(endpoint)
}
