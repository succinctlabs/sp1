use std::sync::Once;

use opentelemetry::global;
use opentelemetry_sdk::{propagation::TraceContextPropagator, runtime, trace, Resource};
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

static INIT: Once = Once::new();

fn build_env_filter(base: Option<EnvFilter>) -> EnvFilter {
    base.unwrap_or(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("debug")))
        .add_directive("p3_keccak_air=off".parse().unwrap())
        .add_directive("p3_fri=off".parse().unwrap())
        .add_directive("p3_dft=off".parse().unwrap())
        .add_directive("p3_challenger=off".parse().unwrap())
        .add_directive("pprof=error".parse().unwrap())
        .add_directive("Pyroscope=error".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("tower=off".parse().unwrap())
}

pub fn init(resource: Resource) {
    INIT.call_once(|| {
        global::set_text_map_propagator(TraceContextPropagator::new());

        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic())
            .with_trace_config(
                trace::config()
                    .with_resource(resource.clone())
                    .with_sampler(trace::Sampler::AlwaysOn),
            )
            .install_batch(runtime::Tokio)
            .unwrap();
        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        let filter = build_env_filter(None);
        tracing_subscriber::registry()
            .with(filter)
            .with(telemetry)
            .with(tracing_subscriber::fmt::layer().compact().with_span_events(FmtSpan::CLOSE))
            .init();
    });
}
