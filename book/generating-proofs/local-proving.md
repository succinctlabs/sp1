# Local Proving

## GPU Proving

## CPU Acceleration

SP1 supports CPU hardware acceleration using AVX256/512 and NEON SIMD instructions. To enable the acceleration, you can use the `RUSTFLAGS` environment variable to generate code that is optimized for your CPU.

**AVX256 / NEON**:
```bash
RUSTFLAGS='-C target-cpu=native' cargo run --release
```

**AVX512**:
```bash
RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' cargo run --release
```

## Enviroment Variables (Advanced)

`SHARD_SIZE`: The number of cycles that will be proven in each "shard" in the SP1 zkVM. This value
must be set to a power of two. 

`SHARD_BATCH_SIZE`: The number of shards that will be proven in parallel. This value can be tuned
depending on how much memory your machine has to improve performance.


## Logging and Tracing Information

You can use `sp1_sdk::utils::setup_logger()` to enable logging information respectively. You can set the logging level with the `RUST_LOG` environment variable.

```rust,noplayground
sp1_sdk::utils::setup_logger();
```

Example of setting the logging level to `info` (other options are `debug`, `trace`, and `warn`):

```bash
RUST_LOG=info cargo run --release
```