# slop-baby-bear

BabyBear prime field with Poseidon2 configuration for SLOP.

Built on [`p3_baby_bear`](https://crates.io/crates/p3_baby_bear) from [Plonky3](https://github.com/Plonky3/Plonky3), with additional functionality:

- Pre-configured Poseidon2 hash parameters for SP1
- Field-specific hash chain configurations

BabyBear is a 31-bit prime field (p = 2^31 - 2^27 + 1) designed for efficient arithmetic in proof systems.

## License

This crate builds on Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
