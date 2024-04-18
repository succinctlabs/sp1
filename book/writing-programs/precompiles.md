# Precompiles

Precompiles are built into the SP1 zkVM and accelerate commonly used operations such as elliptic curve arithmetic and hashing. 
Under the hood, precompiles are implemented as custom tables dedicated to proving one or few operations. **They typically improve the performance
of executing expensive operations by a few order of magnitudes.**

Inside the zkVM, precompiles are exposed as system calls executed through the `ecall` RISC-V instruction.
Each precompile has a unique system call number and implements an interface for the computation.

SP1 also has been designed specifically to make it easy for external contributors to create and extend the zkVM with their own precompiles.
To learn more about this, you can look at implementations of existing precompiles in the [precompiles](https://github.com/succinctlabs/sp1/tree/main/core/src/syscall/precompiles) folder. More documentation on this will be coming soon.

## Supported Precompiles

Typically, we recommend you interact with precompiles through [patches](./patched-crates.md), which are crates patched
to use these precompiles under the hood. However, if you are an advanced user you can interact
with the precompiles directly using extern system calls.

Here is a list of extern system calls that use precompiles.

### SHA256 Extend

Executes the SHA256 extend operation on a word array.

```rust,noplayground
pub extern "C" fn syscall_sha256_extend(w: *mut u32);
```

### SHA256 Compress

Executes the SHA256 compress operation on a word array and a given state.

```rust,noplayground
pub extern "C" fn syscall_sha256_compress(w: *mut u32, state: *mut u32);
```

### Keccak256 Permute

Executes the Keccak256 permutation function on the given state.

```rust,noplayground
pub extern "C" fn syscall_keccak_permute(state: *mut u64);
```

#### Ed25519 Add

Adds two points on the ed25519 curve. The result is stored in the first point.

```rust,noplayground
pub extern "C" fn syscall_ed_add(p: *mut u32, q: *mut u32);
```

#### Ed25519 Decompress.

Decompresses a compressed Ed25519 point.

The second half of the input array should contain the compressed Y point with the final bit as
the sign bit. The first half of the input array will be overwritten with the decompressed point,
and the sign bit will be removed.

```rust,noplayground
pub extern "C" fn syscall_ed_decompress(point: &mut [u8; 64])
```

#### Secp256k1 Add

Adds two Secp256k1 points. The result is stored in the first point.

```rust,noplayground
pub extern "C" fn syscall_secp256k1_add(p: *mut u32, q: *mut u32)
```

#### Secp256k1 Double

Doubles a Secp256k1 point in place.

```rust,noplayground
pub extern "C" fn syscall_secp256k1_double(p: *mut u32)
```

#### Secp256k1 Decompress

Decompess a Secp256k1 point. 

The input array should be 32 bytes long, with the first 16 bytes containing the X coordinate in
big-endian format. The second half of the input will be overwritten with the decompressed point.

```rust,noplayground
pub extern "C" fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);
```

#### Bn254 Add

Adds two Bn254 points. The result is stored in the first point.

```rust,noplayground
pub extern "C" fn syscall_bn254_add(p: *mut u32, q: *mut u32)
```

#### Bn254 Double

Doubles a Bn254 point in place.

```rust,noplayground
pub extern "C" fn syscall_bn254_double(p: *mut u32)
```

#### Bls12-381 Add

Adds two Bls12-381 points. The result is stored in the first point.

```rust,noplayground
pub extern "C" fn syscall_bls12381_add(p: *mut u32, q: *mut u32)
```

#### Bls12-381 Double

Doubles a Bls12-381 point in place.

```rust,noplayground
pub extern "C" fn syscall_bls12381_double(p: *mut u32)
```