use anyhow::{bail, Context, Result};
use std::time::Duration;
use tonic::transport::{ClientTlsConfig, Endpoint, Identity};

/// Configures the endpoint for the gRPC client.
///
/// Sets reasonable settings to handle timeouts and keep-alive.
pub fn configure_endpoint(addr: &str, identity: Option<Identity>) -> Result<Endpoint> {
    let has_identity = identity.is_some();
    if has_identity && !addr.starts_with("https://") {
        bail!("mTLS client identity requires an HTTPS RPC URL");
    }

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
        if let Some(identity) = identity {
            tls_config = tls_config.identity(identity);
        }
        endpoint = if has_identity {
            endpoint.tls_config(tls_config).context("configuring mTLS client identity")?
        } else {
            endpoint.tls_config(tls_config)?
        };
    }

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::configure_endpoint;
    use tonic::transport::Identity;

    const TEST_CERT: &str = r"-----BEGIN CERTIFICATE-----
MIIBjTCCATOgAwIBAgIUWY3Lq5dQkeZfxcTF4UuUAIUR0TUwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRc3AxLXNkay1tdGxzLXRlc3QwHhcNMjYwODI1MDMwOTI4WhcN
MzYwODIyMDMwOTI4WjAcMRowGAYDVQQDDBFzcDEtc2RrLW10bHMtdGVzdDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLmtBB72z7cVnDhCra+5wXBczh+OymKEw7/5
C/qzcuH/dKYxuQdn6nUsRxeImm2xjCEYeTwic3mvU7ltKXIIjhajUzBRMB0GA1Ud
DgQWBBRlnNprvNjkxoFk4/bBtWO+UnfBkTAfBgNVHSMEGDAWgBRlnNprvNjkxoFk
4/bBtWO+UnfBkTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIDlS
IHMpHDa0hGwtMkYZfhXZyDzm1lfMStVOwoV3Ind7AiEA4hp+5F+JII2Fp9E3M6lK
8VDrpentDG8GZv3LLOhoKXo=
-----END CERTIFICATE-----";
    const TEST_KEY: &str = r"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL8Af/fX1VefNox2ZkOQZEe3XEDYfCxEYq2E22VU91j1oAoGCCqGSM49
AwEHoUQDQgAEua0EHvbPtxWcOEKtr7nBcFzOH47KYoTDv/kL+rNy4f90pjG5B2fq
dSxHF4iabbGMIRh5PCJzea9TuW0pcgiOFg==
-----END EC PRIVATE KEY-----";

    #[test]
    fn configures_standard_tls_without_client_identity() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        configure_endpoint("https://localhost", None).unwrap();
    }

    #[test]
    fn configures_mtls_with_explicit_client_identity() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let identity = Identity::from_pem(TEST_CERT, TEST_KEY);
        configure_endpoint("https://localhost", Some(identity)).unwrap();
    }

    #[test]
    fn rejects_invalid_client_identity() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let identity = Identity::from_pem("not a certificate", "not a key");
        let err = configure_endpoint("https://localhost", Some(identity)).unwrap_err().to_string();
        assert!(err.contains("configuring mTLS client identity"));
    }

    #[test]
    fn rejects_client_identity_without_https() {
        let identity = Identity::from_pem(TEST_CERT, TEST_KEY);
        let err = configure_endpoint("http://localhost", Some(identity)).unwrap_err().to_string();
        assert!(err.contains("requires an HTTPS RPC URL"));
    }
}
