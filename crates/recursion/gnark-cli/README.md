# sp1-recursion-gnark-cli

CLI for SP1 Gnark proof generation.

Command-line interface for generating Groth16 and PLONK proofs using Gnark for on-chain verification.

`verify` rejects nonzero exit codes by default.
Pass `--allow-nonzero-exit-code` to opt into experimental verification of nonzero exits.
The Docker caller forwards this flag for nonzero exits when its `experimental` Cargo feature is enabled.
For Docker callers, opt-in requires an image built with support for this flag.
The flag does not bypass cryptographic proof verification or exit-code parsing.

---

Part of [SP1](https://github.com/succinctlabs/sp1), a performant zkVM.
