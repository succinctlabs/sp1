# Offchain Verification

## Rust `no_std` Verification

You can verify SP1 Groth16 and Plonk proofs in `no_std` environments with [`sp1-verifier`](https://docs.rs/sp1-verifier/latest/sp1_verifier/).

`sp1-verifier` is also patched to verify Groth16 and Plonk proofs within the SP1 ZKVM, using
[bn254](https://blog.succinct.xyz/succinctshipsprecompiles/) precompiles. For an example of this, see
the [Groth16 Example](https://github.com/succinctlabs/sp1/tree/main/examples/groth16/).

### Instafllation

Import the following dependency in your `Cargo.toml`:

```toml
sp1-verifier = {version = "3.0.0", default-features = false}
```

### Usage

`sp1-verifier`'s interface is very similar to the solidity verifier's. It exposes two public functions:
[`Groth16Verifier::verify_proof`](https://docs.rs/sp1-verifier/latest/src/sp1_verifier/groth16.rs.html)
and [`PlonkVerifier::verify_proof`](https://docs.rs/sp1-verifier/latest/src/sp1_verifier/plonk.rs.html).

`sp1-verifier` also exposes the Groth16 and Plonk verifying keys as constants, `GROTH16_VK_BYTES` and `PLONK_VK_BYTES`. These
keys correspond to the current SP1 version's official Groth16 and Plonk verifying keys, which are used for verifying proofs generated
using docker or the prover network.

First, generate your groth16/plonk proof with the SP1 SDK. See [here](./onchain/getting-started.md#generating-sp1-proofs-for-onchain-verification)
for more information -- `sp1-verifier` and the solidity verifier expect inputs in the same format.

Next, verify the proof with `sp1-verifier`. The following snippet is from the `sp1-verifier` tests, which use
proofs generated from the Fibonacci example.

```rust,noplayground
// Load the saved proof and extract the proof and public inputs.
let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(proof_file).unwrap();

let proof = sp1_proof_with_public_values.bytes();
let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

// This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
let vkey_hash = "0x00e60860c07bfc6e4c480286c0ddbb879674eb47f84b4ef041cf858b17aa0ed1";

let is_valid =
    crate::Groth16Verifier::verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");
```

Note that the SP1 SDK itself is *not* `no_std` compatible. To use the verifier crate in fully `no_std` environments,
you must input the `sp1_proof_with_public_values.bytes()`, `sp1_proof_with_public_values.public_values.to_vec()`,
and the vkey hash manually. For an example of how to do this, see [Wasm Verification](#wasm-verification).

## Wasm Verification

The [`example-sp1-wasm-verifier`](https://github.com/succinctlabs/example-sp1-wasm-verifier) demonstrates how to
verify SP1 proofs in wasm. For a more detailed explanation of the process, please see the [README](https://github.com/succinctlabs/example-sp1-wasm-verifier/blob/main/README.md).

At a high level, the process is as follows:

1. Create wasm bindings for `sp1-verifier`, using tools like `wasm-bindgen` and `wasm-pack`.
2. Serialize proof bytes and `SP1ProofWithPublicValues` structs to JSON.
3. Load the JSON proof in your wasm runtime and verify it with your wasm bindings.
