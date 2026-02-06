# slop-challenger

Fiat-Shamir challenger with SP1-specific extensions.

Built on [`p3_challenger`](https://crates.io/crates/p3_challenger) from [Plonky3](https://github.com/Plonky3/Plonky3), with additional functionality:

- `FromChallenger` trait needed to enable challengers on GPU.
- `IopCtx` trait defining a common collection of trait bounds appearing throughout the proof system.
- `VariableLengthChallenger` trait for variable-length challenge absorption.

The challenger provides the randomness needed to make interactive proofs non-interactive via the Fiat-Shamir heuristic.

## License

This crate builds on Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
