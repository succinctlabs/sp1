use std::sync::Once;

use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    INIT.call_once(|| {
        let default_filter = "off";
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
        tracing_subscriber::fmt::Subscriber::builder()
            .compact()
            .with_file(false)
            .with_target(false)
            .with_thread_names(false)
            .with_env_filter(env_filter)
            .finish()
            .init();
    });
}
