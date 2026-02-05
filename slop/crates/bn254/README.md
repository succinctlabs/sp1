# slop-bn254

BN254 scalar field with Poseidon2 configuration for outer proving.

Built on [`p3_bn254_fr`](https://crates.io/crates/p3_bn254_fr) from [Plonky3](https://github.com/Plonky3/Plonky3), with additional definitions for use in SP1:

- Poseidon2 hash configuration for the BN254 scalar field
- Fixed parameters for SP1's outer proving layer

BN254 (also known as alt-bn128) is used for the final proof layer, enabling efficient on-chain verification through precompiled contracts on Ethereum.

## License

This crate builds on Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
