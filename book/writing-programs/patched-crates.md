# Patched Crates

We maintain forks of commonly used libraries in blockchain infrastructure to significantly accelerate the execution of certain operations.
Under the hood, we use [precompiles](./precompiles.md) to achieve tremendous performance improvements in proof generation time.

**If you know of a library or library version that you think should be patched, please open an issue or a pull request!**

## Supported Libraries

| Crate Name          | Repository                                                                            | Notes            | Versions              |
|---------------------|---------------------------------------------------------------------------------------|------------------|-----------------------|
| sha2                | [sp1-patches/RustCrypto-hashes](https://github.com/sp1-patches/RustCrypto-hashes)     | sha256           | 0.9.8, 0.10.6, 0.10.8 |
| sha3                | [sp1-patches/RustCrypto-hashes](https://github.com/sp1-patches/RustCrypto-hashes)     | keccak256        | 0.9.8, 0.10.6, 0.10.8 |
| bigint              | [sp1-patches/RustCrypto-bigint](https://github.com/sp1-patches/RustCrypto-bigint)     | bigint           | 0.5.5                 |
| tiny-keccak         | [sp1-patches/tiny-keccak](https://github.com/sp1-patches/tiny-keccak)                 | keccak256        | 2.0.2                 |
| curve25519-dalek    | [sp1-patches/curve25519-dalek](https://github.com/sp1-patches/curve25519-dalek)       | ed25519 verify   | 4.1.3, 3.2.0          |
| curve25519-dalek-ng | [sp1-patches/curve25519-dalek-ng](https://github.com/sp1-patches/curve25519-dalek-ng) | ed25519 verify   | 4.1.1                 |
| ed25519-consensus   | [sp1-patches/ed25519-consensus](http://github.com/sp1-patches/ed25519-consensus)      | ed25519 verify   | 2.1.0                 |
| ed25519-dalek       | [sp1-patches/ed25519-dalek](http://github.com/sp1-patches/ed25519-dalek)              | ed25519 verify   | 1.0.1                 |
| ecdsa-core          | [sp1-patches/signatures](http://github.com/sp1-patches/signatures)                    | secp256k1 verify | 0.16.8, 0.16.9        |
| secp256k1           | [sp1-patches/rust-secp256k1](http://github.com/sp1-patches/rust-secp256k1)            | secp256k1 verify | 0.29.0, 0.29.1        |
| substrate-bn        | [sp1-patches/bn](https://github.com/sp1-patches/bn)                                   | BN254            | 0.6.0                 |
| bls12_381           | [sp1-patches/bls12_381](https://github.com/sp1-patches/bls12_381)                     | BLS12-381        | 0.8.0                 |

## Using Patched Crates

To use the patched libraries, you can use corresponding patch entries in your program's `Cargo.toml` such as:

```toml
[patch.crates-io]
sha2-v0-9-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", tag = "sha2-v0.9.8-patch-v1" }
sha2-v0-10-6 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", tag = "sha2-v0.10.6-patch-v1" }
sha2-v0-10-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", tag = "sha2-v0.10.8-patch-v1" }
sha3-v0-9-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", tag = "sha3-v0.9.8-patch-v1" }
sha3-v0-10-6 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", tag = "sha3-v0.10.6-patch-v1" }
sha3-v0-10-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", tag = "sha3-v0.10.8-patch-v1" }
crypto-bigint = { git = "https://github.com/sp1-patches/RustCrypto-bigint", tag = "crypto_bigint-v0.5.5-patch-v1" }
tiny-keccak = { git = "https://github.com/sp1-patches/tiny-keccak", tag = "tiny_keccak-v2.0.2-patch-v1" }
curve25519-dalek = { git = "https://github.com/sp1-patches/curve25519-dalek", tag = "curve25519_dalek-v4.1.3-patch-v1" }
curve25519-dalek-ng = { git = "https://github.com/sp1-patches/curve25519-dalek-ng", tag = "curve25519_dalek_ng-v4.1.1-patch-v1" }
ed25519-consensus = { git = "https://github.com/sp1-patches/ed25519-consensus", tag = "ed25519_consensus-v2.1.0-patch-v1" }
ecdsa-core = { git = "https://github.com/sp1-patches/signatures", package = "ecdsa", tag = "ecdsa-v0.16.9-patch-v1" }
secp256k1 = { git = "https://github.com/sp1-patches/rust-secp256k1", tag = "secp256k1-v0.29.0-patch-v1" }
substrate-bn = { git = "https://github.com/sp1-patches/bn", tag = "substrate_bn-v0.6.0-patch-v1" }
bls12_381 = { git = "https://github.com/sp1-patches/bls12_381", tag = "bls12_381-v0.8.0-patch-v1" }

```

If you are patching a crate from Github instead of from crates.io, you need to specify the
repository in the patch section. For example:

```toml
[patch."https://github.com/RustCrypto/hashes"]
sha3 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", tag = "sha3-v0.10.8-patch-v1"  }
```

An example of using patched crates is available in our [Tendermint Example](https://github.com/succinctlabs/sp1/blob/main/examples/tendermint/program/Cargo.toml#L22-L25).

## Ed25519 Acceleration

To accelerate Ed25519 operations, you'll need to patch crates depending on if you're using the `ed25519-consensus` or `ed25519-dalek` library in your program or dependencies.

Generally, `ed25519-consensus` has better performance than `ed25519-dalek` by a factor of 2.

### Patches

Apply the following patches based on what crates are in your dependencies.

- `ed25519-consensus`

  ```toml
  ed25519-consensus = { git = "https://github.com/sp1-patches/ed25519-consensus", tag = "ed25519_consensus-v2.1.0-patch-v1" }
  ```

  Note: The curve operations for Ed25519 occur mainly inside of `curve25519-dalek-ng`, but the crate also exposes
  a `u32_backend` feature flag which accelerates signature recovery by 10% over the default `u64_backend`, which is why
  `ed25519-consensus` is patched rather than `ed25519-dalek`.

- `ed25519-dalek`

  If using `ed25519-dalek` version `2.1`, you can patch it with the following:

  ```toml
  curve25519-dalek = { git = "https://github.com/sp1-patches/curve25519-dalek", tag = "curve25519_dalek-v4.1.3-patch-v1" }
  ```

  If using `ed25519-dalek` version `1.0.1`, you can patch it with the following:

  ```toml
  ed25519-dalek = { git = "https://github.com/sp1-patches/ed25519-dalek", tag = "ed25519_dalek-v1.0.1-patch-v1" }
  ```

  Note: We need to patch the underlying Ed25519 curve operations in the `curve25519-dalek` crate. `ed25519-dalek`
  version `2.1` uses `curve25519-dalek` version `4.1.3`, while `1.0.1` uses `3.2.0`. For version `2.1`, we patch
  `curve25519-dalek` directly, while for version `1.0.1`, we patch `ed25519-dalek`.

- `curve25519-dalek`

  ```toml
  curve25519-dalek = { git = "https://github.com/sp1-patches/curve25519-dalek", tag = "curve25519_dalek-v4.1.3-patch-v1" }
  ```

- `curve25519-dalek-ng`

  ```toml
  curve25519-dalek-ng = { git = "https://github.com/sp1-patches/curve25519-dalek-ng", tag = "curve25519_dalek_ng-v4.1.1-patch-v1" }
  ```

## Secp256k1 Acceleration

To accelerate Secp256k1 operations, you'll need to patch `k256` or `secp256k1` depending on your usage.

Generally, if a crate you're using (ex. `revm`) has support for using `k256` instead of `secp256k1`, you should use `k256`.

### Patches

Apply the following patches based on what crates are in your dependencies.

- `k256`

  ```toml
  ecdsa-core = { git = "https://github.com/sp1-patches/signatures", package = "ecdsa", tag = "ecdsa-v0.16.9-patch-v1" }
  ```

  Note: The curve operations for `k256` are inside of the `ecdsa-core` crate, so you don't need to patch `k256` itself, and just patching `ecdsa-core` is enough.

- `secp256k1`

  ```toml
  secp256k1 = { git = "https://github.com/sp1-patches/rust-secp256k1", tag = "secp256k1-v0.29.0-patch-v1" }
  ```

## BN254 Acceleration

To accelerate BN254 (Also known as BN128 and Alt-BN128), you will need to patch the `substrate-bn` crate.

### Patches

Apply the patch by adding the following to your list of dependencies:

```rust
substrate-bn = { git = "https://github.com/sp1-patches/bn", tag = "substrate_bn-v0.6.0-patch-v1" }
```

### Performance Benchmarks for Patched `substrate-bn` in `revm`

| Operation | Standard `substrate-bn` Cycles | Patched `substrate-bn` Cycles | Times Faster |
| --------- | ------------------------------ | ----------------------------- | ------------ |
| run-add   | 170,298                        | 111,615                       | 1.52         |
| run-mul   | 1,860,836                      | 243,830                       | 7.64         |
| run-pair  | 255,627,625                    | 11,528,503                    | 22.15        |

Note: The operations `run-add`, `run-mul`, and `run-pair` are from the `revm` crate, specifically from the file `crates/precompile/src/bn128.rs` on GitHub. In the patched version of the `substrate-bn` crate, these functions utilize SP1's BN254 Fp precompiles.

To accelerate [revm](https://github.com/bluealloy/revm) in SP1 using the BN254 patched crate, replace the `substrate-bn` crate with the patched crate by adding the following to `crates/precompile/Cargo.toml`:

```toml
bn = { git = "https://github.com/sp1-patches/bn", package = "substrate-bn", tag = "substrate_bn-v0.6.0-patch-v1" }
```

## BLS12-381 Acceleration

To accelerate BLS12-381 operations, you'll need to patch the `bls12_381` crate. Apply the following patch by adding the following to your list of dependencies:

```toml
bls12_381 = { git = "https://github.com/sp1-patches/bls12_381", tag = "bls12_381-v0.8.0-patch-v1" }
```

This patch significantly improves the performance of BLS12-381 operations, making it essential for applications that rely heavily on these cryptographic primitives.

### Performance Benchmarks for Patched `bls12_381` in [`kzg-rs`](https://github.com/succinctlabs/kzg-rs)

| Test                                   | Unpatched Cycles | Patched Cycles | Improvement (x faster) |
| -------------------------------------- | ---------------- | -------------- | ---------------------- |
| Verify blob KZG proof                  | 265,322,934      | 27,166,173     | 9.77x                  |
| Verify blob KZG proof batch (10 blobs) | 1,228,277,089    | 196,571,578    | 6.25x                  |
| Evaluate polynomial in evaluation form | 90,717,711       | 59,370,556     | 1.53x                  |
| Compute challenge                      | 63,400,511       | 57,341,532     | 1.11x                  |
| Verify KZG proof                       | 212,708,597      | 9,390,640      | 22.65x                 |

## Troubleshooting

### Verifying Patch Usage: Cargo

You can check if the patch was applied by using cargo's tree command to print the dependencies of the crate you patched.

```bash
cargo tree -p sha2@0.9.8
```

Next to the package name, it should have a link to the Github repository that you patched with.

Ex.

```text
sha2 v0.9.8 (https://github.com/sp1-patches/RustCrypto-hashes?branch=patch-sha2-v0.9.8#afdbfb09)
├── ...
```

### Verifying Patch Usage: SP1

To check if a precompile is used by your program, you can view SP1's ExecutionReport, which is returned when executing a program with `execute`. In `ExecutionReport` you can view the `syscall_counts` map to view if a specific syscall was used.

For example, if you wanted to check `sha256` was used, you would look for `SHA_EXTEND` and `SHA_COMPRESS` in `syscall_counts`.

An example of this is available in our [Patch Testing Example](https://github.com/succinctlabs/sp1/blob/dd032eb23949828d244d1ad1f1569aa78155837c/examples/patch-testing/script/src/main.rs).

### Cargo Version Issues

If you encounter issues with version commits on your patches, you should try updating the patched crate manually.

```bash
cargo update -p <patch-crate-name>
```

If you encounter issues relating to cargo / git, you can try setting `CARGO_NET_GIT_FETCH_WITH_CLI`:

```bash
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo update -p <patch-crate-name>
```

You can permanently set this value in `~/.cargo/config`:

```toml
[net]
git-fetch-with-cli = true
```
