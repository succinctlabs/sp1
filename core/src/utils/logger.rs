use std::sync::Once;

use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

static INIT: Once = Once::new();

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    INIT.call_once(|| {
        let default_filter = "off";
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_filter))
            .add_directive("p3_keccak_air=off".parse().unwrap())
            .add_directive("p3_fri=off".parse().unwrap())
            .add_directive("p3_dft=off".parse().unwrap())
            .add_directive("p3_challenger=off".parse().unwrap());

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    });
}
