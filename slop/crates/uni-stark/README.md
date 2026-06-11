# slop-uni-stark

The symbolic constraint layer for SLOP AIRs.

Vendored from [`p3_uni_stark`](https://crates.io/crates/p3_uni_stark) ([Plonky3](https://github.com/Plonky3/Plonky3), `0.4.3-succinct`), reduced to the symbolic pieces SP1 uses (the univariate STARK prover/verifier are not used and were dropped), and extended with the global trace group: `Entry::Global`, a global matrix in `SymbolicAirBuilder`, and `global_width` parameters on `get_symbolic_constraints` / `get_max_constraint_degree`.

## License

This crate contains code vendored from Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
