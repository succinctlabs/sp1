# SP1 Fork for PVUGC (BLS12-377)

This is a minimal fork of [SP1](https://github.com/succinctlabs/sp1) that changes the final Groth16 wrapper from BN254 to BLS12-377 for PVUGC integration.

## Changes Made

### 1. `crates/recursion/gnark-ffi/go/sp1/build.go`

Added `BuildGroth16Bls12_377()` function that compiles and sets up the Groth16 circuit for BLS12-377:

```go
// Key change: ecc.BN254 → ecc.BLS12_377
r1cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &circuit)
```

### 2. `crates/recursion/gnark-ffi/go/sp1/prove.go`

Added `ProveGroth16Bls12_377()` function with BLS12-377 global caches:

```go
var globalR1cs377 constraint.ConstraintSystem = groth16.NewCS(ecc.BLS12_377)
var globalPk377 groth16.ProvingKey = groth16.NewProvingKey(ecc.BLS12_377)
```

### 3. `crates/recursion/gnark-ffi/go/main.go`

Added CGO exports:
- `ProveGroth16Bls12_377`
- `BuildGroth16Bls12_377`
- `FreeGroth16Bls12_377Proof`

## What's Unchanged

- **SP1 Core**: All BabyBear STARK proving remains unchanged
- **Recursion layers**: Reduce, Compress, Shrink - all unchanged
- **Circuit logic**: The wrapper circuit verifies the same SP1 recursive proof
- **Constraint IR**: The opcodes and simulation logic are identical

## Usage

### Build the Circuit (One-time setup)

```bash
# Generate pk_377, vk_377 for BLS12-377
BuildGroth16Bls12_377("/path/to/data")
```

### Prove

```bash
# Generate BLS12-377 Groth16 proof
proof := ProveGroth16Bls12_377("/path/to/data", "/path/to/witness.json")
```

### In Rust (PVUGC)

```rust
use pvugc::sp1_bridge::{
    decode_sp1_proof_hex,
    parse_gnark_proof_bls12_377,
};

// Decode SP1's hex output
let proof_bytes = decode_sp1_proof_hex(&sp1_proof.raw_proof)?;
let proof = parse_gnark_proof_bls12_377(&proof_bytes)?;

// Use with PVUGC outer circuit
```

#### Note on proof/VK wire formats

- This fork standardizes on gnark's **`WriteRawTo` / `ReadFrom`** encoding for Groth16 proof + verifying key.
- `raw_proof` is the hex encoding of gnark `(*Proof).WriteRawTo(...)`.
- `encoded_proof` is unused for Groth16(BLS12-377) and is left empty (no Solidity encoding).

## Upstream Tracking

- **Base commit**: Shallow clone from `main` branch
- **SP1 repo**: https://github.com/succinctlabs/sp1

## Security Notes

1. **New trusted setup required**: BLS12-377 requires its own trusted setup
2. **VK changes**: The verification key will be different from BN254
3. **Proof format**: Same structure, different curve points


