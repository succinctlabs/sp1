# Patched Crates

We maintain forks of commonly used libraries in blockchain infrastructure to significantly accelerate the execution of certain operations.
Under the hood, we use [precompiles](./precompiles.md) to achieve tremendous performance improvements in proof generation time.

**If you know of a library or library version that you think should be patched, please open an issue or a pull request!**

## Supported Libraries

| Crate Name          | Repository                                                                            | Notes                  |
| ------------------- | ------------------------------------------------------------------------------------- | ---------------------- |
| sha2                | [sp1-patches/RustCrypto-hashes](https://github.com/sp1-patches/RustCrypto-hashes)     | sha256                 |
| sha3                | [sp1-patches/RustCrypto-hashes](https://github.com/sp1-patches/RustCrypto-hashes)     | keccak256              |
| bigint              | [sp1-patches/RustCrypto-bigint](https://github.com/sp1-patches/RustCrypto-bigint)     | bigint                 |
| tiny-keccak         | [sp1-patches/tiny-keccak](https://github.com/sp1-patches/tiny-keccak)                 | keccak256              |
| ed25519-consensus   | [sp1-patches/ed25519-consensus](http://github.com/sp1-patches/ed25519-consensus)      | ed25519 verify         |
| curve25519-dalek-ng | [sp1-patches/curve25519-dalek-ng](https://github.com/sp1-patches/curve25519-dalek-ng) | ed25519 verify         |
| curve25519-dalek    | [sp1-patches/curve25519-dalek](https://github.com/sp1-patches/curve25519-dalek)       | ed25519 verify         |
| revm-precompile     | [sp1-patches/revm](https://github.com/sp1-patches/revm)                               | ecrecover precompile   |
| reth-primitives     | [sp1-patches/reth](https://github.com/sp1-patches/reth)                               | ecrecover transactions |

## Using Patched Crates

To use the patched libraries, you can use corresponding patch entries in your program's `Cargo.toml` such as:

```toml
[patch.crates-io]
sha2-v0-9-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", branch = "patch-sha2-v0.9.8" }
sha2-v0-10-6 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", branch = "patch-sha2-v0.10.6" }
sha2-v0-10-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", branch = "patch-sha2-v0.10.8" }
sha3-v0-9-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", branch = "patch-sha3-v0.9.8" }
sha3-v0-10-6 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", branch = "patch-sha3-v0.10.6" }
sha3-v0-10-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", branch = "patch-sha3-v0.10.8" }
crypto-bigint = { git = "https://github.com/sp1-patches/RustCrypto-bigint", branch = "patch-v0.5.5" }
curve25519-dalek = { git = "https://github.com/sp1-patches/curve25519-dalek", branch = "patch-v4.1.1" }
curve25519-dalek-ng = { git = "https://github.com/sp1-patches/curve25519-dalek-ng", branch = "patch-v4.1.1" }
ed25519-consensus = { git = "https://github.com/sp1-patches/ed25519-consensus", branch = "patch-v2.1.0" }
tiny-keccak = { git = "https://github.com/sp1-patches/tiny-keccak", branch = "patch-v2.0.2" }
revm = { git = "https://github.com/sp1-patches/revm", branch = "patch-v5.0.0" }
reth-primitives = { git = "https://github.com/sp1-patches/reth", default-features = false, branch = "sp1-reth" }
```

If you are patching a crate from Github instead of from crates.io, you need to specify the
repository in the patch section. For example:

```toml
[patch."https://github.com/RustCrypto/hashes"]
sha3 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha3", branch = "patch-sha3-v0.10.8" }
```

An example of using patched crates is available in our [Tendermint Example](https://github.com/succinctlabs/sp1/blob/main/examples/tendermint/program/Cargo.toml#L22-L25).

### Verifying Patch Usage: Cargo

You can check if the patch was applied by using cargo's tree command to print the dependencies of the crate you patched.

```bash
cargo tree -p sha2
cargo tree -p sha2@0.9.8
```

Next to the package name, it should have a link to the Github repository that you patched with.

### Verifying Patch Usage: SP1

To check if a precompile is used by your program, you can observe SP1's log output. Make sure to setup the logger with `sp1_sdk::utils::setup_logger()` and run your program with `RUST_LOG=info`.

In the example below, note how the `sha256_extend` precompile was reported as being used eight times.

```bash
2024-07-03T04:46:33.753527Z  INFO prove_core: execution report (syscall counts):
2024-07-03T04:46:33.753550Z  INFO prove_core:   8 sha256_extend
2024-07-03T04:46:33.753550Z  INFO prove_core:   8 commit
2024-07-03T04:46:33.753553Z  INFO prove_core:   8 commit_deferred_proofs
2024-07-03T04:46:33.753554Z  INFO prove_core:   4 write
2024-07-03T04:46:33.753555Z  INFO prove_core:   1 halt
```

### Troubleshooting

You may also need to update your `Cargo.lock` file. For example:

```bash
cargo update -p ed25519-consensus
```

If you encounter issues relating to cargo / git, you can try setting `CARGO_NET_GIT_FETCH_WITH_CLI`:

```bash
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo update -p ed25519-consensus
```

You can permanently set this value in `~/.cargo/config`:

```toml
[net]
git-fetch-with-cli = true
```
