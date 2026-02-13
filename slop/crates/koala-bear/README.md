# slop-koala-bear

KoalaBear prime field with Poseidon2 configuration for SLOP.

Built on [`p3_koala_bear`](https://crates.io/crates/p3_koala_bear) from [Plonky3](https://github.com/Plonky3/Plonky3), with additional functionality:

- Pre-configured Poseidon2 hash parameters optimized for SP1
- Field-specific hash chain configurations

KoalaBear is a 31-bit prime field (p=2^31-2^24+1) designed for efficient arithmetic, similar to BabyBear but with a more efficient Poseidon2 arithmetization.

## License

This crate builds on Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
