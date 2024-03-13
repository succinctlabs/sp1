use std::sync::Once;

use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
            .add_directive("p3_challenger=off".parse().unwrap());
        tracing_subscriber::fmt::Subscriber::builder()
            .compact()
            .with_file(false)
            .with_target(false)
            .with_thread_names(false)
            .with_env_filter(env_filter)
            .with_span_events(FmtSpan::CLOSE)
            .finish()
            .init();
    });
}
