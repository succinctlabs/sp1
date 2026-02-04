# sp1-gpu-tracing

Tracing and debugging instrumentation for SP1-GPU.

Provides tracing infrastructure for profiling and debugging the GPU prover, with support for Jaeger telemetry export and detailed timing information.

## Usage with Jaeger

```bash
# Start Jaeger
docker run -d -p4318:4318 -p16686:16686 jaegertracing/all-in-one:latest

# Run with tracing
cargo run --release -p sp1-gpu-perf --bin e2e -- --program fibonacci-200m --trace telemetry

# View traces at http://localhost:16686
```

---

Part of [SP1-GPU](https://github.com/succinctlabs/sp1/tree/dev/sp1-gpu), the GPU-accelerated prover for SP1.
