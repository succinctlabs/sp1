# SP1 Verifier

This crate provides verifiers for SP1 Groth16 and Plonk zero-knowledge proofs. These proofs are expected
to be generated using the [SP1 SDK](../sdk).

## Features

Groth16 and Plonk proof verification are supported in `no-std` environments. Verification in the
SP1 zkVM context is patched, in order to make use of the
[bn254 precompiles](https://blog.succinct.xyz/succinctshipsprecompiles/).

### Pre-generated verification keys

Verification keys for Groth16 and Plonk are stored in the [`bn254-vk`](./bn254-vk/) directory. These
vkeys are used to verify all SP1 proofs.

These vkeys are the same as those found locally in
`~/.sp1/circuits/<circuit_name>/<version>/<circuit_name>_vk.bin`, and should be automatically
updated after every release.

## Tests

Run tests with the following command:

```sh
cargo test --package sp1-verifier
```

These tests generate a groth16/plonk proof and verify it.

## Acknowledgements

Adapted from [@Bisht13's](https://github.com/Bisht13/gnark-bn254-verifier) `gnark-bn254-verifier` crate.
