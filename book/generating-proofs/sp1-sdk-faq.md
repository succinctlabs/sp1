# FAQ

## Logging and Tracing Information

You can use `sp1_sdk::utils::setup_logger()` to enable logging information respectively. You can set the logging level with the `RUST_LOG` environment variable.

```rust,noplayground
sp1_sdk::utils::setup_logger();
```

Example of setting the logging level to `info` (other options are `debug`, `trace`, and `warn`):

```bash
RUST_LOG=info cargo run --release
```


## Optimize Local Proving with CPU Acceleration

SP1 supports CPU hardware acceleration using AVX256/512 and NEON SIMD instructions. To enable the acceleration, you can use the `RUSTFLAGS` environment variable to generate code that is optimized for your CPU.

**AVX2 / NEON**:
```bash
RUSTFLAGS='-C target-cpu=native' cargo run --release
```

**AVX512**:
```bash
RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' cargo run --release
```

## GPU Proving

Note that SP1 has a GPU prover that is currently in beta, but it is not yet supported in the `sp1-sdk` crate and has experimental support in the `sp1-prover` crate. Our prover network currently runs the SP1 GPU prover, so the recommended way to generate proofs with GPU is via the prover network.