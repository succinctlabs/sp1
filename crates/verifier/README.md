# SP1 Verifier

This crate provides verifiers for SP1 Groth16 and Plonk zero-knowledge proofs. These proofs are expected
to be generated using the [SP1 SDK](../sdk).

## Features

Groth16 proof verification is supported in completely no-std environments. 

Plonk proof verification requires randomness, so it requires a `getrandom` implementation in the 
runtime. Environments like wasm and the sp1 zkvm are capable of providing this. 

We provide the `getrandom` feature flag for this purpose, which is enabled by default.

## Tests

Run tests with the following command:

```sh
cargo test --features getrandom --package sp1-verifier
```

These tests verify the proofs in the [`test_binaries`](./test_binaries) directory. These test binaries
were generated from the fibonacci [groth16](../../examples/fibonacci/script/bin/groth16_bn254.rs) and 
[plonk](../../examples/fibonacci/script/bin/plonk_bn254.rs) examples. You can reproduce these proofs
from the examples by running `cargo run --bin groth16_bn254` and `cargo run --bin plonk_bn254` from the
[`examples/fibonacci`](../../examples/fibonacci/) directory.

# Acknowledgements

Adapted from [@Bisht13's](https://github.com/Bisht13/gnark-bn254-verifier) `gnark-bn254-verifier` crate.

