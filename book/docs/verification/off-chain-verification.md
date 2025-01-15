import ProgramMain from "@site/static/examples_groth16_program_src_main.rs.mdx";
import ProgramScript from "@site/static/examples_groth16_script_src_main.rs.mdx";

# Offchain Verification

## Rust `no_std` Verification

You can verify SP1 Groth16 and Plonk proofs in `no_std` environments with [`sp1-verifier`](https://docs.rs/sp1-verifier/latest/sp1_verifier/).

`sp1-verifier` is also patched to verify Groth16 and Plonk proofs within the SP1 ZKVM, using
[bn254](https://blog.succinct.xyz/succinctshipsprecompiles/) precompiles. For an example of this, see
the [Groth16 Example](https://github.com/succinctlabs/sp1/tree/main/examples/groth16/).

### Installation

Import the following dependency in your `Cargo.toml`:

```toml
sp1-verifier = {version = "4.0.0", default-features = false}
```

### Usage

`sp1-verifier`'s interface is very similar to the solidity verifier's. It exposes two public functions:
[`Groth16Verifier::verify_proof`](https://docs.rs/sp1-verifier/latest/src/sp1_verifier/groth16.rs.html)
and [`PlonkVerifier::verify_proof`](https://docs.rs/sp1-verifier/latest/src/sp1_verifier/plonk.rs.html).

`sp1-verifier` also exposes the Groth16 and Plonk verifying keys as constants, `GROTH16_VK_BYTES` and `PLONK_VK_BYTES`. These
keys correspond to the current SP1 version's official Groth16 and Plonk verifying keys, which are used for verifying proofs generated
using docker or the prover network.

First, generate your groth16/plonk proof with the SP1 SDK. See [here](./onchain/getting-started#generating-sp1-proofs-for-onchain-verification)
for more information -- `sp1-verifier` and the solidity verifier expect inputs in the same format.

Next, verify the proof with `sp1-verifier`. The following snippet is from the [Groth16 example program](https://github.com/succinctlabs/sp1/tree/dev/examples/groth16/), which verifies a Groth16 proof within SP1 using `sp1-verifier`.

<ProgramMain />

Here, the proof, public inputs, and vkey hash are read from stdin. See the following snippet to see how these values are generated.

<ProgramScript />

> Note that the SP1 SDK itself is _not_ `no_std` compatible.

## Wasm Verification

The [`example-sp1-wasm-verifier`](https://github.com/succinctlabs/example-sp1-wasm-verifier) demonstrates how to
verify SP1 proofs in wasm. For a more detailed explanation of the process, please see the [README](https://github.com/succinctlabs/example-sp1-wasm-verifier/blob/main/README.md).
