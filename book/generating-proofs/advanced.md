# Advanced Usage

## Execution Only

We recommend that during development of large programs (> 1 million cycles) that you do not generate proofs each time.
Instead, you should have your script only execute the program with the RISC-V runtime and read `public_values`. Here is an example:

```rust,noplayground
{{#include ../../examples/fibonacci-io/script/bin/execute.rs}}
```

If execution of your program succeeds, then proof generation should succeed as well! (Unless there is a bug in our zkVM implementation.)

## Compressed Proofs

With the `ProverClient`, the default `prove` function generates a proof that is succinct, but can have size that scales with the number of cycles of the program. To generate a compressed proof of constant size, you can use the `prove_compressed` function instead. This will use STARK recursion to generate a proof that is constant size (around 7Kb), but will be slower than just calling `prove`, as it will use recursion to combine the core SP1 proof into a single constant-sized proof.

```rust,noplayground
{{#include ../../examples/fibonacci-io/script/bin/compressed.rs}}
```

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

**Tracing:**

To enable tracing information, which provides more detailed timing information, you can use the following environment variable: # TODO

```bash
RUST_TRACER=info cargo run --release
```

## AVX-512 Acceleration

## Performance

For maximal performance, you should run proof generation with the following command and vary your `shard_size` depending on your program's number of cycles.

```rust,noplayground
SHARD_SIZE=4194304 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```

You can also use the `SAVE_DISK_THRESHOLD` env variable to control whether shards are saved to disk or not.
This is useful for controlling memory usage.

```rust,noplayground
SAVE_DISK_THRESHOLD=64 SHARD_SIZE=2097152 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```
