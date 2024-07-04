# Generating Proofs: Basics

All the methods you'll need for generating proofs are included in the `sp1_sdk` crate. Most importantly, you'll need to use the `ProverClient` to setup a proving key and verifying key for your program and then use the `prove` and `verify` methods to generate and verify proofs.

To make this more concrete, let's walk through a simple example of generating a proof for a Fiboancci program inside the zkVM.

## Example: Fibonacci

```rust,noplayground
{{#include ../../examples/fibonacci/script/src/main.rs}}
```

You can run the above script in the `script` directory with `RUST_LOG=info cargo run --release`.