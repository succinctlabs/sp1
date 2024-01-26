use std::sync::Once;

use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    INIT.call_once(|| {
        tracing_subscriber::fmt::Subscriber::builder()
            .without_time()
            .with_env_filter(EnvFilter::from_default_env())
            .finish()
            .init();
    });
}
