use std::sync::Once;

use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

use crate::nvtx::NvtxLayer;

static INIT: Once = Once::new();

/// Initializes the tracing subscriber.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
#[allow(dead_code)]
pub fn init_tracer() {
    INIT.call_once(|| {
        let default_filter = "off";
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_filter))
            .add_directive("p3_keccak_air=off".parse().unwrap())
            .add_directive("p3_fri=off".parse().unwrap())
            .add_directive("p3_dft=off".parse().unwrap())
            .add_directive("p3_challenger=off".parse().unwrap())
            .add_directive("p3_merkle_tree=off".parse().unwrap());

        tracing_subscriber::fmt::Subscriber::builder()
            .compact()
            .with_file(false)
            .with_target(false)
            .with_thread_names(false)
            .with_env_filter(env_filter)
            .with_span_events(FmtSpan::CLOSE)
            .finish()
            .with(NvtxLayer)
            .init();
    });
}
