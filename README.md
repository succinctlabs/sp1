# Succinct zkVM

## Install

Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed. Install the "cargo prove" CLI.
```
git clone https://github.com/succinctlabs/vm succinct-vm
cd succinct-vm
cd cli
cargo install --locked --path .
```

You will need to install our custom toolchain to compile programs. If you are on a supported architecture 
(i.e., MacOS or Linux), install the toolchain using a prebuilt release.
```
cargo prove install-toolchain
```

Otherwise, you will need to build the toolchain from source.
```
cargo prove build-toolchain
```

## Quickstart

Just "cargo prove".

```
cd examples/fibonacci
cargo prove
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