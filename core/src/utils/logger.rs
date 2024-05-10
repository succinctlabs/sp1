use std::fs::File;
use std::sync::Once;

use tracing_forest::ForestLayer;
use tracing_subscriber::fmt::format::FmtSpan;
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

        // if the RUST_LOGGER environment variable is set, use it to determine which logger to configure
        // (tracing_forest or tracing_subscriber)
        // otherwise, default to 'flat'
        let logger_type = std::env::var("RUST_LOGGER").unwrap_or_else(|_| "flat".to_string());
        match logger_type.as_str() {
            "forest" => {
                Registry::default()
                    .with(env_filter)
                    .with(ForestLayer::default())
                    .init();
            }
            "flat" => {
                // Write to file if the SP1_LOG_DIR env variable is set
                if let Ok(log_dir) = std::env::var("SP1_LOG_DIR") {
                    dbg!(log_dir.clone());
                    let file = File::create(log_dir).expect("failed to create log file");
                    dbg!("created file");
                    tracing_subscriber::fmt::Subscriber::builder()
                        .compact()
                        .with_ansi(false)
                        .with_file(false)
                        .with_target(false)
                        .with_thread_names(false)
                        .with_env_filter(env_filter)
                        .with_writer(file)
                        .with_span_events(FmtSpan::CLOSE)
                        .finish()
                        .init();
                } else {
                    dbg!("no log dir");
                    tracing_subscriber::fmt::Subscriber::builder()
                        .compact()
                        .with_file(false)
                        .with_target(false)
                        .with_thread_names(false)
                        .with_env_filter(env_filter)
                        // .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                        .with_span_events(FmtSpan::CLOSE)
                        .finish()
                        .init();
                }
            }
            _ => {
                panic!("Invalid logger type: {}", logger_type);
            }
        }
    });
}
