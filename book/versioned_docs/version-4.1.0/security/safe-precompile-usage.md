# Safe Usage of SP1 Precompiles

This section outlines the key assumptions and properties of each precompile. As explained in [Precompiles](../writing-programs/precompiles.mdx), we recommend you to interact with precompiles through [patches](../writing-programs/patched-crates.md). Advanced users interacting directly with the precompiles are expected to ensure these assumptions are met.

## Do not use direct ECALL
If you need to interact with the precompiles directly, you must use the API described in [Precompiles](../writing-programs/precompiles.mdx) instead of making the `ecall` directly using unsafe Rust. As some of our syscalls have critical functionalities and complex security properties around them, **we highly recommend not calling the syscalls directly with `ecall`**. For example, directly calling `HALT` to stop the program execution leads to security vulnerabilities. As in our [security model](./security-model.md), it is critical for safe usage that the program compiled into SP1 is correct. 

## Alignment of Pointers

For all precompiles, any pointer with associated data must be a valid pointer aligned to a four-byte boundary. This requirement applies to all precompiles related to hashing, field operations, and elliptic curve operations. 

## Canonical Field Inputs

Certain precompiles handle non-native field arithmetic, such as field operation and elliptic curve precompiles. These precompiles take field inputs as arrays of `u32` values. In such cases, the `u32` values must represent the field element in its canonical form. For example, in a finite field `Fp`, the value `1` must be represented by `u32` limbs that encode `1`, rather than `p + 1` or `2 * p + 1`. Using non-canonical representations may result in unverifiable SP1 proofs. Note that our field operation and elliptic curve operation precompiles are constrained to return field elements in their canonical representations.

## Elliptic Curve Precompiles

The elliptic curve precompiles assume that inputs are valid elliptic curve points. Since this validity is not enforced within the precompile circuits, it is the responsibility of the user program to verify that the points lie on the curve. Given valid elliptic curve points as inputs, the precompile will perform point addition or doubling as expected.

For Weierstrass curves, the `add` precompile additionally constrains that the two elliptic curve points have different `x`-coordinates over the base field. Attempting to double a point by sending two equal curve points to the `add` precompile will result in unverifiable proofs. Additionally, cases where an input or output point is a point at infinity cannot be handled by the `add` or `double` precompile. It is the responsibility of the user program to handle such edge cases of Weierstrass addition correctly when invoking these precompiles.

## U256 Precompile

The `sys_bigint` precompile efficiently constrains the computation of `(x * y) % modulus`, where `x, y, modulus` are all `uint256`. Here, the precompile requires that `x * y < 2^256 * modulus` for the resulting SP1 proof to be verifiable. This condition is satisfied, for example, when at least one of `x` or `y` is canonical, (i.e., less than the `modulus`). It is the responsibility of the user program to ensure that this requirement is met.