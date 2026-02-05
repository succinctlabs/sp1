# slop-multilinear

Multilinear polynomial extensions for SLOP.

Provides representations and operations for multilinear polynomials, which are fundamental to sumcheck-based proof systems. A multilinear polynomial is uniquely determined by its evaluations on the Boolean hypercube.

## Features

- `Mle` - Multilinear extension representation
- `PaddedMle` - A dense representation of a multilinear polynomial with many zeroes. 
- `Point` - A utility struct for multi-variate evaluation.
- Efficient evaluation, folding, and restriction operations
- Lagrange and monomial basis utilities
- Multilinear PCS (Polynomial Commitment Scheme) trait definitions

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
