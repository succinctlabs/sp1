# slop-jagged

Jagged polynomial handling for sparse-to-dense conversion.

Implements the jagged sparse-to-dense polynomial adapter, which converts evaluation claims on variable-sized tables (as used in SP1 Hypercube arithmetization) into evaluation claims on densely packed BaseFold/WHIR instances.

## Features

- Jagged polynomial implementation for variable-size tables
- Implementation of the "jagged assist" protocol for the evaluation of the jagged polynomial.
- Implementation of the protocol end-to-end (prover and verifier), generic in a `MultilinearPcsProver` or `MultilinearPcsVerifier`.
- Utility functions for integration with stacked BaseFold.

## References

- [Jagged Paper](https://eprint.iacr.org/2025/917)

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
