# slop-air

AIR (Algebraic Intermediate Representation) traits and virtual columns for the SLOP library.

Vendored from [`p3_air`](https://crates.io/crates/p3_air) ([Plonky3](https://github.com/Plonky3/Plonky3), `0.4.3-succinct`) and extended with the *global* trace group: chips read three separate row views — `preprocessed()`, `global()`, and `main()` — via `PairBuilder`, `GlobalBuilder`, and `AirBuilder`. `PairCol` has a `Global` variant and `VirtualPairCol::apply` takes three slices.

AIRs are the foundation for proof systems (including SP1 Hypercube), defining the constraints that valid execution traces must satisfy.

## License

This crate contains code vendored from Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
