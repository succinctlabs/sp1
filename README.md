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

## Acknowledgements

We would like to acknowledge the projects below whose previous work has been instrumental in making this project a reality.

- [Plonky3](https://github.com/Plonky3/Plonky3): The Succinct zkVM's prover is powered by the Plonky3 toolkit.
- [Valida](https://github.com/valida-xyz/valida): The Succinct zkVM cross-table lookups, prover, and chip design, including constraints, are inspired by Valida.
- [RISC0](https://github.com/risc0/risc0): The Succinct zkVM rust toolchain, install/build scripts, and our RISCV runtime borrow code from RISC0.