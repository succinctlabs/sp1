# slop-maybe-rayon

Re-exports [`p3_maybe_rayon`](https://crates.io/crates/p3_maybe_rayon) from [Plonky3](https://github.com/Plonky3/Plonky3) for use in the SLOP library.

This crate provides optional parallelism utilities that abstract over Rayon. It allows SLOP to use parallel iterators when the `parallel` feature is enabled, while falling back to sequential execution otherwise.

## License

This crate re-exports code from Plonky3, which is licensed under MIT/Apache-2.0.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
