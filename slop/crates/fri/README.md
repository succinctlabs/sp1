# slop-fri

Re-exports [`p3_fri`](https://crates.io/crates/p3_fri) from [Plonky3](https://github.com/Plonky3/Plonky3) for use in the SLOP library.

This crate provides FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity) protocol implementations. FRI is used to prove that a committed polynomial has low degree, forming a core component of STARK proof systems.
For the BaseFold implementation in `slop-basefold-prover`, all that is needed from this module is `fold_even_odd`, the function which performs
the FRI folding step on Reed-Solomon codewords.

## License

This crate re-exports code from Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
