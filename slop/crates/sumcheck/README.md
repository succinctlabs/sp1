# slop-sumcheck

Sumcheck protocol implementation for multilinear polynomials.

Implements the sumcheck protocol, a fundamental building block for succinct proofs. The sumcheck protocol allows a prover to convince a verifier of the sum of a multilinear polynomial over the Boolean hypercube with logarithmic communication.

## Features

- Prover for sumcheck over products of multilinear polynomials
- Verifier with efficient round-by-round checking
- Support for batched sumcheck proofs
- Integration with SLOP's tensor and multilinear infrastructure

## References

- [Sumcheck Protocol](https://people.cs.georgetown.edu/jthaler/sumcheck.pdf)

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
