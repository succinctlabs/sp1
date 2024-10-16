# Generating Proofs: Basics

All the methods you'll need for generating proofs are included in the `sp1_sdk` crate. Most importantly, you'll need to use the `ProverClient` to setup a proving key and verifying key for your program and then use the `execute`, `prove` and `verify` methods to execute your program, and generate and verify proofs.

To make this more concrete, let's walk through a simple example of generating a proof for a Fibonacci program inside the zkVM.

## Example: Fibonacci

```rust,noplayground
{{#include ../../examples/fibonacci/script/src/main.rs}}
```

You can run the above script in the `script` directory with `RUST_LOG=info cargo run --release`. Note that running the above script will generate a proof locally.

<div class="warning">
WARNING: Local proving often is much slower than the prover network and for certain proof types (e.g. Groth16, PLONK) require a significant amount of RAM and will likely not work on a laptop.
</div>

We recommend using the [prover network](./prover-network.md) to generate proofs. Read more about the [recommended workflow](./recommended-workflow.md) for developing with SP1.
