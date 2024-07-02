# Advanced Usage

## Execution Only

We recommend that during the development of large programs (> 1 million cycles) you do not generate proofs each time.
Instead, you should have your script only execute the program with the RISC-V runtime and read `public_values`. Here is an example:

```rust,noplayground
{{#include ../../examples/fibonacci/script/bin/execute.rs}}
```

If the execution of your program succeeds, then proof generation should succeed as well! (Unless there is a bug in our zkVM implementation.)

## Compressed Proofs

With the `ProverClient`, the default `prove` function generates a proof that is succinct, but can have size that scales with the number of cycles of the program. To generate a compressed proof of constant size, you can use the `prove_compressed` function instead. This will use STARK recursion to generate a proof that is constant size (around 7Kb), but will be slower than just calling `prove`, as it will use recursion to combine the core SP1 proof into a single constant-sized proof.

```rust,noplayground
{{#include ../../examples/fibonacci/script/bin/compressed.rs}}
```

You can run the above script with `RUST_LOG=info cargo run --bin compressed --release` from `examples/fibonacci/script`.

## Logging and Tracing Information

You can use `utils::setup_logger()` to enable logging information respectively. You should only use one or the other of these functions.

**Logging:**

```rust,noplayground
utils::setup_logger();
```

You must run your command with:

```bash
RUST_LOG=info cargo run --release
```

## CPU Acceleration

To enable CPU acceleration, you can use the `RUSTFLAGS` environment variable to enable the `target-cpu=native` flag when running your script. This will enable the compiler to generate code that is optimized for your CPU.

```bash
RUSTFLAGS='-C target-cpu=native' cargo run --release
```

Currently there is support for AVX512 and NEON SIMD instructions. For NEON, you must also enable the `sp1-sdk` feature `neon` in your script crate's `Cargo.toml` file.

```toml
sp1-sdk = { git = "https://github.com/succinctlabs/sp1", features = ["neon"] }
```

## Performance

For maximal performance, you should run proof generation with the following command and vary your `shard_size` depending on your program's number of cycles.

```rust,noplayground
SHARD_SIZE=4194304 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```

## Memory Usage

To reduce memory usage, set the `SHARD_BATCH_SIZE` environment variable depending on how much RAM
your machine has. A higher number will use more memory, but will be faster.

```rust,noplayground
SHARD_BATCH_SIZE=1 SHARD_SIZE=2097152 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```
