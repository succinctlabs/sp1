# Precompiles

Precompiles are built into the Curta zkVM and accelerate commonly used operations such as elliptic curve arithmetic and hashing. 
Under the hood, precompiles are implemented as custom tables dedicated to proving one or few operations. **They typically improve the performance
of executing expensive operations by a few order of magnitudes.**

Inside the zkVM, precompiles are exposed as system calls executed through the `ecall` RISC-V instruction.
Each precompile has a unique system call number and implements an interface for the computation.

Curta zkVM also has been designed specifically to make it easy for external contributors to create and extend the zkVM with their own precompiles.
To learn more about this, go to [Custom Precompiles]().

## Supported Precompiles

Typically, we recommend you interact with precompiles through [patches](./patched-crates.md), which are crates patched
to use these precompiles under the hood. However, if you are an advanced user you can interact
with the precompiles directly using extern system calls.

### SHA256 Extend

Executes the SHA256 extend operation on a word array.

```rust
pub extern "C" fn syscall_sha256_extend(w: *mut u32);
```

### SHA256 Compress

Executes the SHA256 compress operation on a word array and a given state.

```rust
pub extern "C" fn syscall_sha256_compress(w: *mut u32, state: *mut u32);
```

### Keccak256 Permute

Executes the Keccak256 permutation function on the given state.

```rust
pub extern "C" fn syscall_keccak_permute(state: *mut u64);
```

#### Ed25519 Add

Adds two points on the ed25519 curve. The result is stored in the first point.

```rust
pub extern "C" fn syscall_ed_add(p: *mut u32, q: *mut u32);
```

#### Ed25519 Decompress.

Decompresses a compressed Ed25519 point.

The second half of the input array should contain the compressed Y point with the final bit as
the sign bit. The first half of the input array will be overwritten with the decompressed point,
and the sign bit will be removed.

```rust
pub extern "C" fn syscall_ed_decompress(point: &mut [u8; 64])
```

#### Secp256k1 Add

Adds two Secp256k1 points. The result is stored in the first point.

```rust
pub extern "C" fn syscall_secp256k1_add(p: *mut u32, q: *mut u32)
```

#### Secp256k1 Double

Doubles a Secp256k1 point. The result is stored in the first point.

```rust
pub extern "C" fn syscall_secp256k1_double(p: *mut u32)
```

#### Secp256k1 Decompress

Decompess a Secp256k1 point. 

The input array should be 32 bytes long, with the first 16 bytes containing the X coordinate in
big-endian format. The second half of the input will be overwritten with the decompressed point.

```rust
pub extern "C" fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);
```