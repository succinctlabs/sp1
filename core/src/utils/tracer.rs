use std::env;

use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// A tracer to benchmark the performance of the vm.
///
/// Set the `RUST_TRACER` environment variable to be set to `info` or `debug`.
/// ! DEPRECATED: don't use this function, use `setup_logger` instead.
pub fn setup_tracer() {
    let tracer_config = env::var("RUST_TRACER").unwrap_or_else(|_| "none".to_string());
    let mut env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::OFF.into())
        .with_default_directive("log::=off".parse().unwrap())
        .from_env_lossy();
    if tracer_config == "info" {
        env_filter = env_filter.add_directive("sp1_core=info".parse().unwrap());
    } else if tracer_config == "debug" {
        env_filter = env_filter.add_directive("sp1_core=debug".parse().unwrap());
    }
    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}
