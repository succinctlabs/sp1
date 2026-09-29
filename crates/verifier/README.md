# SP1 Verifier

This crate contains primitives for verifying SP1 proofs generated using the [SP1 SDK](../sdk).

It is split into the following modules:
- `compressed`: Verifiers for SP1 "compressed" proofs.
- `groth16`: Verifiers for Groth16 proofs.
- `plonk`: Verifiers for Plonk proofs.


## Features

The default `full` feature includes Groth16, Plonk, and compressed proof types and verification.
Disable default features to use only the Groth16 and Plonk verifiers on constrained `no_std`
targets such as `wasm32-unknown-unknown`.

Verification in the SP1 zkVM context is patched in order to make use of the
[bn254 precompiles](https://blog.succinct.xyz/succinctshipsprecompiles/).

### Pre-generated verification keys

Verification keys for Groth16 and Plonk are stored in the [`vk-artifacts`](./vk-artifacts/) directory. These
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
