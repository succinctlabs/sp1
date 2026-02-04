# slop-jagged

Jagged polynomial handling for sparse-to-dense conversion.

Implements the jagged sparse-to-dense polynomial adapter, which converts evaluation claims on variable-sized tables (as used in SP1 Hypercube arithmetization) into evaluation claims on densely packed BaseFold/WHIR instances.

## Features

- Jagged polynomial representation for variable-size tables
- Sparse-to-dense conversion with "jagged assist"
- BaseFold and Hadamard product integration
- Prover and verifier for jagged evaluation claims
- Sumcheck integration for jagged polynomials

## References

- [Jagged Paper](https://eprint.iacr.org/2025/917)

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
