use std::env;
use std::{sync::Once, time::Duration};
use tracing_forest::ForestLayer;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

static INIT: Once = Once::new();

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

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

/// A tracer to benchmark the performance of the vm.
///
/// Set the `RUST_TRACER` environment variable to be set to `info` or `debug`.
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

pub struct StageProgressBar {
    pb: ProgressBar,
    current_stage: u32,
    current_stage_name: String,
    total_stages: String,
}

impl StageProgressBar {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let pb = ProgressBar::new(1);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green}")
                .unwrap()
                .progress_chars("#>-")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
        );
        pb.enable_steady_tick(Duration::from_millis(50));

        let mp = MultiProgress::new();
        let pb = mp.add(pb);

        Self {
            pb,
            current_stage: 0,
            current_stage_name: "Starting".to_string(),
            total_stages: "?".to_string(),
        }
    }

    pub fn update(
        &mut self,
        stage: u32,
        total_stages: u32,
        stage_name: &str,
        stage_progress: Option<(u32, u32)>,
    ) {
        if stage > self.current_stage {
            self.pb.set_position(0);
            self.pb.reset_eta();
        }
        if let Some(progress) = stage_progress {
            self.pb.set_position(progress.0.into());
            self.pb.set_length(progress.1.into());
            self.pb.set_style(
                ProgressStyle::with_template("\n{msg}\n{spinner:.green} [{elapsed}] [{wide_bar:.cyan/blue}] {pos}/{len} (eta {eta})")
                    .unwrap()
                    .progress_chars("#>-")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
        } else {
            self.pb.set_style(
                ProgressStyle::with_template("\n{msg}\n{spinner:.green} [{elapsed}]")
                    .unwrap()
                    .progress_chars("#>-")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
        }

        self.current_stage = stage;
        self.total_stages = total_stages.to_string();
        self.current_stage_name = stage_name.to_string();
        self.pb
            .set_message(format!("[{}/{}] {}", stage, total_stages, stage_name));
    }

    pub fn finish(&mut self) {
        self.pb.finish_and_clear();
    }
}
