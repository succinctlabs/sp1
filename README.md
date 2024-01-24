# Succinct zkVM

## Install

Install Rust.
```
curl https://sh.rustup.rs -sSf | sh
```

Install the "cargo prove" CLI tool.
```
git clone https://github.com/succinctlabs/vm succinct-vm
cd succinct-vm
cd cli && cargo install --locked --path .
```

If you are on a supported architecture, install the Succinct Rust Toolchain using a prebuilt release.
```
cargo prove install-toolchain
```

Otherwise, you will need to build the toolchain from source.
```
cargo prove build-toolchain
```

## Profile

To get a performance breakdown of proving, run the profiler.
```
cd core && RUST_TRACER=debug cargo run --bin profile --release --features perf -- --program ../programs/sha2
```

## Benchmark

To benchmark the proving time of programs with statistical guarantees, run the benchmark.
```
cd core && cargo bench --features perf
```