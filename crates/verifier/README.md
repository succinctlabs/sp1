# SP1 Verifier

This crate provides verifiers for SP1 Groth16 and Plonk zero-knowledge proofs. These proofs are expected
to be generated using the [SP1 SDK](../sdk).

## Features

Groth16 and Plonk proof verification are supported in `no-std` environments.

## Tests

Run tests with the following command:

```sh
cargo test --package sp1-verifier
```

These tests verify the proofs in the [`test_binaries`](./test_binaries) directory. These test binaries
were generated from the fibonacci [groth16](../../examples/fibonacci/script/bin/groth16_bn254.rs) and
[plonk](../../examples/fibonacci/script/bin/plonk_bn254.rs) examples. You can reproduce these proofs
from the examples by running `cargo run --bin groth16_bn254` and `cargo run --bin plonk_bn254` from the
[`examples/fibonacci`](../../examples/fibonacci/) directory.

## Acknowledgements

Adapted from [@Bisht13's](https://github.com/Bisht13/gnark-bn254-verifier) `gnark-bn254-verifier` crate.
