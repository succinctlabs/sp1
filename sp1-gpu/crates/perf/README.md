# sp1-gpu-perf

Performance benchmarks and testing utilities for SP1-GPU.

Provides benchmarking tools for measuring GPU prover performance, including end-to-end proving times and component-level metrics. This crate is used for development and optimization, not published to crates.io.

## Usage

```bash
# Run end-to-end benchmark
cargo run --release -p sp1-gpu-perf --bin e2e -- --program fibonacci-200m
```

---

Part of [SP1-GPU](https://github.com/succinctlabs/sp1/tree/dev/sp1-gpu), the GPU-accelerated prover for SP1.
