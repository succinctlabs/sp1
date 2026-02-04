# slop-multilinear

Multilinear polynomial extensions for SLOP.

Provides representations and operations for multilinear polynomials, which are fundamental to sumcheck-based proof systems. A multilinear polynomial is uniquely determined by its evaluations on the Boolean hypercube.

## Features

- `Mle` - Multilinear extension representation
- `PaddedMle` - Padded MLE for uniform sizing
- `Point` - Evaluation point representation
- Efficient evaluation, folding, and restriction operations
- Lagrange basis utilities
- PCS (Polynomial Commitment Scheme) integration

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
