# slop-dft

Discrete Fourier Transform operations for tensors.

Built on [`p3_dft`](https://crates.io/crates/p3_dft) from [Plonky3](https://github.com/Plonky3/Plonky3), with additional functionality:

- `Dft` trait for integration of the Plonky3 trait with SLOP's tensor infrastructure.

DFT operations are essential for polynomial arithmetic in proof systems, enabling efficient evaluation and interpolation.

## License

This crate builds on Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
