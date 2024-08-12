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