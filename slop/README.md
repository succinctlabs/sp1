# SLOP - Succinct Library of Polynomials

SLOP is a library of polynomial interactive oracle proofs used in [SP1 Hypercube](https://github.com/succinctlabs/sp1).

## Plonky3 Foundation

SLOP builds on [Plonky3](https://github.com/Plonky3/Plonky3) by Polygon. Several crates in this library are thin wrappers around Plonky3 primitives to maintain API compatibility with SP1, while others are original implementations.

### Plonky3 Re-exports

The following crates re-export Plonky3 primitives with minimal modifications:

- `slop-air` - Re-exports `p3_air`
- `slop-fri` - Re-exports `p3_fri`
- `slop-poseidon2` - Re-exports `p3_poseidon2`
- `slop-symmetric` - Re-exports `p3_symmetric`
- `slop-matrix` - Re-exports `p3_matrix`
- `slop-maybe-rayon` - Re-exports `p3_maybe_rayon`
- `slop-uni-stark` - Re-exports `p3_uni_stark`
- `slop-keccak-air` - Re-exports `p3_keccak_air`

Additional crates build on Plonky3 with SP1-specific extensions:

- `slop-algebra` - Built on `p3_field` with univariate polynomial operations
- `slop-baby-bear`, `slop-koala-bear`, `slop-bn254` - Field implementations with custom Poseidon2 configurations
- `slop-challenger` - Built on `p3_challenger` with additional traits
- `slop-commit` - Built on `p3_commit` with message/rounds modules
- `slop-dft` - Built on `p3_dft` with tensor DFT trait
- `slop-merkle-tree` - Built on `p3_merkle_tree` with tensor commitment scheme

### Original Implementations

The following are original implementations developed for SP1:

- **Data structures**: `slop-tensor`, `slop-alloc`, `slop-multilinear`
- **Protocols**: `slop-sumcheck`, `slop-basefold`, `slop-whir`, `slop-spartan`, `slop-jagged`, `slop-stacked`, `slop-pgspcs`

## Features

SLOP contains CPU implementations of:

1. **Data structures and memory allocation** - The `Backend` trait and `Tensor` struct for underlying data processed in SP1 Hypercube polynomial IOPs.

2. **Sumcheck protocol** - Sumchecks for products of multilinear polynomials.

3. **Polynomial commitment schemes** - [BaseFold](https://eprint.iacr.org/2023/1705) and [WHIR](https://eprint.iacr.org/2024/1586) multilinear polynomial commitment schemes.

4. **Spartan proof system** - [Spartan](https://eprint.iacr.org/2019/550) for rank-one constraint systems with the "pretty good sparse polynomial commitment scheme" (PGSPCS).

5. **Jagged adapter** - The [jagged](https://eprint.iacr.org/2025/917) sparse-to-dense polynomial adapter for converting evaluation claims on SP1 hypercube arithmetization tables into claims on densely packed BaseFold/WHIR instances.

## Audit Status

As of November 2025, only the jagged, BaseFold, stacked BaseFold, and sumcheck **verifiers** are audited. These can be used in contexts outside SP1 Hypercube, though some API choices limit generality (e.g., the verifier must know ahead of time how many rounds of commitments there will be). Other protocol implementations are not audited for production use.

## License

This project is licensed under MIT/Apache-2.0. Plonky3-derived code is used under its MIT/Apache-2.0 license.
