# slop-sumcheck

Sumcheck protocol implementation for multilinear polynomials.

Implements the sumcheck protocol, a fundamental building block for succinct proofs. The sumcheck protocol allows a prover to convince a verifier of the sum of a multivariate polynomial over the Boolean hypercube with logarithmic communication.

## Features

- `SumcheckPoly` traits to reduce code re-use between different sumchecks.
- Prover for sumcheck, generic over a `SumcheckPolyFirstRound` implementation.
- Sumcheck verifier
- Support for batched sumcheck proofs
- Implementation of the `SumcheckPoly` traits for the `Mle` type.

## References

- [Sumcheck Protocol](https://people.cs.georgetown.edu/jthaler/sumcheck.pdf)

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
