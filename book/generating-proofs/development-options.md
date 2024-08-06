# Development Options

## Execution Only

We recommend that during the development of large programs (> 1 million cycles) you do not generate proofs each time.
Instead, you should have your script only execute the program with the RISC-V runtime and read `public_values`. Here is an example:

```rust,noplayground
{{#include ../../examples/fibonacci/script/bin/execute.rs}}
```

If the execution of your program succeeds, then proof generation should succeed as well! (Unless there is a bug in our zkVM implementation.)

## Logging and Tracing Information

You can use `sp1_sdk::utils::setup_logger()` to enable logging information respectively. You can set the logging level with the `RUST_LOG` environment variable.

```rust,noplayground
sp1_sdk::utils::setup_logger();
```

Example of setting the logging level to `info` (other options are `debug`, `trace`, and `warn`):

```bash
RUST_LOG=info cargo run --release
```