use std::sync::Once;

static INIT: Once = Once::new();

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    INIT.call_once(|| {
        env_logger::Builder::from_default_env()
            .format_timestamp(None)
            .init();
    });
}
