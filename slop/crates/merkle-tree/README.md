# slop-merkle-tree

Merkle tree commitments with tensor commitment scheme support.

Built on [`p3_merkle_tree`](https://crates.io/crates/p3_merkle_tree) from [Plonky3](https://github.com/Plonky3/Plonky3), with additional functionality:

- Tensor Commitment Scheme (TCS) for committing to multi-dimensional data
- `TensorCsProver` trait for tensor commitment provers
- `ComputeTcsOpenings` for computing openings at specific indices
- `FieldMerkleTreeProver` using Poseidon2

Enables efficient commitment to the tensor data structures used throughout SP1's proof system.

## License

This crate builds on Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
