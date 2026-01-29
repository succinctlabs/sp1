# Precompile GPU Tracegen Implementation Checklist

This document tracks the GPU tracegen implementation status for precompile chips.

## SHA-256 Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| ShaExtendChip | `Sha256Extend` | [ ] | [x] | [ ] | `precompiles/sha256.rs` |
| ShaExtendControlChip | `Sha256ExtendControl` | [ ] | [x] | [ ] | `precompiles/sha256.rs` |
| ShaCompressChip | `Sha256Compress` | [ ] | [x] | [ ] | `precompiles/sha256.rs` |
| ShaCompressControlChip | `Sha256CompressControl` | [ ] | [x] | [ ] | `precompiles/sha256.rs` |

## Edwards Curve Precompiles (Ed25519)

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| EdAddAssignChip | `Ed25519Add` | [ ] | [x] | [ ] | `precompiles/edwards.rs` |
| EdDecompressChip | `Ed25519Decompress` | [ ] | [x] | [ ] | `precompiles/edwards.rs` |

## Secp256k1 Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| WeierstrassDecompressChip | `K256Decompress` | [ ] | [x] | [ ] | `precompiles/weierstrass.rs` |
| WeierstrassAddAssignChip | `Secp256k1Add` | [ ] | [x] | [ ] | `precompiles/weierstrass.rs` |
| WeierstrassDoubleAssignChip | `Secp256k1Double` | [ ] | [x] | [ ] | `precompiles/weierstrass.rs` |

## Secp256r1 Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| WeierstrassDecompressChip | `P256Decompress` | [ ] | [x] | [ ] | `precompiles/weierstrass.rs` |
| WeierstrassAddAssignChip | `Secp256r1Add` | [ ] | [x] | [ ] | `precompiles/weierstrass.rs` |
| WeierstrassDoubleAssignChip | `Secp256r1Double` | [ ] | [x] | [ ] | `precompiles/weierstrass.rs` |

## Keccak Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| KeccakPermuteChip | `KeccakP` | [ ] | [x] | [ ] | `precompiles/keccak.rs` |
| KeccakPermuteControlChip | `KeccakPControl` | [ ] | [x] | [ ] | `precompiles/keccak.rs` |

## BN254 Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| WeierstrassAddAssignChip | `Bn254Add` | [ ] | [x] | [ ] | `precompiles/bn254.rs` |
| WeierstrassDoubleAssignChip | `Bn254Double` | [ ] | [x] | [ ] | `precompiles/bn254.rs` |
| FpOpChip | `Bn254Fp` | [ ] | [x] | [ ] | `precompiles/bn254.rs` |
| Fp2MulAssignChip | `Bn254Fp2Mul` | [ ] | [x] | [ ] | `precompiles/bn254.rs` |
| Fp2AddSubAssignChip | `Bn254Fp2AddSub` | [ ] | [x] | [ ] | `precompiles/bn254.rs` |

## BLS12-381 Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| WeierstrassAddAssignChip | `Bls12381Add` | [ ] | [x] | [ ] | `precompiles/bls12381.rs` |
| WeierstrassDoubleAssignChip | `Bls12381Double` | [ ] | [x] | [ ] | `precompiles/bls12381.rs` |
| WeierstrassDecompressChip | `Bls12381Decompress` | [ ] | [x] | [ ] | `precompiles/bls12381.rs` |
| FpOpChip | `Bls12381Fp` | [ ] | [x] | [ ] | `precompiles/bls12381.rs` |
| Fp2MulAssignChip | `Bls12381Fp2Mul` | [ ] | [x] | [ ] | `precompiles/bls12381.rs` |
| Fp2AddSubAssignChip | `Bls12381Fp2AddSub` | [ ] | [x] | [ ] | `precompiles/bls12381.rs` |

## Uint256 Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| Uint256MulChip | `Uint256Mul` | [ ] | [x] | [ ] | `precompiles/uint256.rs` |
| Uint256OpsChip | `Uint256Ops` | [ ] | [x] | [ ] | `precompiles/uint256.rs` |
| U256x2048MulChip | `U256x2048Mul` | [ ] | [x] | [ ] | `precompiles/uint256.rs` |

## Other Precompiles

| Chip | Variant | GPU Impl | Stub | Tests | File |
|------|---------|----------|------|-------|------|
| MProtectChip | `Mprotect` | [ ] | [x] | [ ] | `precompiles/other.rs` |
| Poseidon2Chip | `Poseidon2` | [ ] | [x] | [ ] | `precompiles/other.rs` |

## Summary

- **Total precompile chips**: 31
- **GPU implemented**: 0
- **Stubs created**: 31
- **Tests passing**: 0

## File Structure

```
crates/tracegen/src/riscv/precompiles/
├── mod.rs
├── sha256.rs       # SHA-256 extend/compress
├── edwards.rs      # Ed25519 add/decompress
├── weierstrass.rs  # secp256k1/r1 decompress/add/double
├── keccak.rs       # Keccak permute
├── bn254.rs        # BN254 curve + field ops
├── bls12381.rs     # BLS12-381 curve + field ops
├── uint256.rs      # Uint256 mul/ops, U256x2048
└── other.rs        # Mprotect, Poseidon2
```

## Priority Order (Suggested)

Based on typical usage patterns:

1. **High Priority** (commonly used):
   - SHA-256 (Sha256Extend, Sha256Compress)
   - Keccak (KeccakP)
   - Secp256k1 (K256Decompress, Secp256k1Add, Secp256k1Double)

2. **Medium Priority**:
   - Ed25519 (Ed25519Add, Ed25519Decompress)
   - BN254 (pairing-friendly curve)
   - Uint256 ops

3. **Lower Priority**:
   - BLS12-381 (less common)
   - Secp256r1 (P-256)
   - Poseidon2, Mprotect
