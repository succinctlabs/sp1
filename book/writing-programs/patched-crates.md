# Patched Crates

We maintain forks of commonly used libraries in blockchain infrastructure to significantly accelerate the execution of certain operations.
Under the hood, we use [precompiles](./precompiles.md) to acheive tremendous performance improvements in proof generation time.

**If you know of a library that you think should be patched, please open an issue or a pull request!**

## Supported Libraries

| Crate Name          | Repository                                             |
|---------------------|--------------------------------------------------------|
| sha2                | [succinctlabs/RustCrypto-hashes](https://github.com/succinctlabs/RustCrypto-hashes-private) |
| ed25519-consensus   | [succinctlabs/ed25519-consensus](https://github.com/succinctlabs/ed25519-consensus-private) |
| alloy-core          | [succinctlabs/alloy-core](https://github.com/succinctlabs/alloy-core-private) |
| tiny-keccak         | [succinctlabs/tiny-keccak](https://github.com/succinctlabs/tiny-keccak-private) |
| dalek-ng           | [succinctlabs/dalek-ng](https://github.com/succinctlabs/dalek-ng-private) |

## Using Patched Crates

To use the patched libraries, you can use the `patch` section of the `Cargo.toml` as follows:

```toml
[patch.crates-io]
sha2-v0-9-8 = { git = "https://github.com/succinctbot/RustCrypto-hashes.git", package = "sha2", branch = "v0.9.8" }
sha2-v0-10-6 = { git = "https://github.com/succinctbot/RustCrypto-hashes.git", package = "sha2", branch = "main" }
time = { git = "https://github.com/time-rs/time.git", rev = "v0.3.28" }
ed25519-consensus = { git = "https://github.com/succinctlabs/ed25519-consensus-private.git" }
tiny-keccak = { git = "https://github.com/succinctlabs/tiny-keccak-private.git" }
```

You may also need to update your `Cargo.lock` file. For example:

```bash
cargo update -p ed25519-consensus
```

If you want to patch with a private repo, you have to use the following adjustment in your `Cargo.toml`:

```toml
ed25519-consensus = { git = "https://github.com/succinctlabs/ed25519-consensus-private.git" }
```
and use the following command to apply the patch (assuming you have your ssh keys setup properly with Github):
```
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo update -p ed25519-consensus
```

### Sanity Checks

**You must make sure your patch is in the workspace root, otherwise it will not be applied.**

You can check if the patch was applied by running a command like the following:
```bash
cargo tree -p sha2
cargo tree -p sha2@0.9.8
```

Next to the package name, it should have a link to the Github repository that you patched with.