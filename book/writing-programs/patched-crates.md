# Patched Crates

We maintain forks of commonly used libraries in blockchain infrastructure to significantly accelerate the execution of certain operations.
Under the hood, we use [precompiles](./precompiles.md) to acheive tremendous performance improvements in proof generation time.

**If you know of a library or library version that you think should be patched, please open an issue or a pull request!**

## Supported Libraries

| Crate Name          | Repository                                                                            | Notes                  |
| ------------------- | ------------------------------------------------------------------------------------- | ---------------------- |
| sha2                | [sp1-patches/RustCrypto-hashes](https://github.com/sp1-patches/RustCrypto-hashes)     | sha256                 |
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
sha2-v0-9-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", branch = "patch-v0.9.8" }
sha2-v0-10-6 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", branch = "patch-v0.10.6" }
sha2-v0-10-8 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", branch = "patch-v0.10.8" }
curve25519-dalek = { git = "https://github.com/sp1-patches/curve25519-dalek", branch = "patch-v4.1.1" }
curve25519-dalek-ng = { git = "https://github.com/sp1-patches/curve25519-dalek-ng", branch = "patch-v4.1.1" }
ed25519-consensus = { git = "https://github.com/sp1-patches/ed25519-consensus", branch = "patch-v2.1.0" }
tiny-keccak = { git = "https://github.com/sp1-patches/tiny-keccak", branch = "patch-v2.0.2" }
revm = { git = "https://github.com/sp1-patches/revm", branch = "patch-v5.0.0" }
reth-primitives = { git = "https://github.com/sp1-patches/reth", default-features = false, branch = "sp1-reth" }
```

You may also need to update your `Cargo.lock` file. For example:

```bash
cargo update -p ed25519-consensus
```

If you encounter issues relating to cargo / git, you can try setting `CARGO_NET_GIT_FETCH_WITH_CLI`:

```
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo update -p ed25519-consensus
```

You can permanently set this value in `~/.cargo/config`:

```toml
[net]
git-fetch-with-cli = true
```

### Sanity Checks

**You must make sure your patch is in the workspace root, otherwise it will not be applied.**

You can check if the patch was applied by running a command like the following:

```bash
cargo tree -p sha2
cargo tree -p sha2@0.9.8
```

Next to the package name, it should have a link to the Github repository that you patched with.

**Checking whether a precompile is used**

To check if a precompile is used by your program, when running the script to generate a proof, make sure to use the `RUST_LOG=info` environment variable and set up `utils::setup_logger()` in your script. Then, when you run the script, you should see a log message like the following:

```bash
2024-03-02T19:10:39.570244Z  INFO runtime.run(...): ... 
2024-03-02T19:10:39.570244Z  INFO runtime.run(...): ... 
2024-03-02T19:10:40.003907Z  INFO runtime.prove(...): Sharding the execution record.
2024-03-02T19:10:40.003916Z  INFO runtime.prove(...): Generating trace for each chip.
2024-03-02T19:10:40.003918Z  INFO runtime.prove(...): Record stats before generate_trace (incomplete): ShardStats {
    nb_cpu_events: 7476561,
    nb_add_events: 2126546,
    nb_mul_events: 11116,
    nb_sub_events: 54075,
    nb_bitwise_events: 646940,
    nb_shift_left_events: 142595,
    nb_shift_right_events: 274016,
    nb_divrem_events: 0,
    nb_lt_events: 81862,
    nb_field_events: 0,
    nb_sha_extend_events: 0,
    nb_sha_compress_events: 0,
    nb_keccak_permute_events: 2916,
    nb_ed_add_events: 0,
    nb_ed_decompress_events: 0,
    nb_weierstrass_add_events: 0,
    nb_weierstrass_double_events: 0,
    nb_k256_decompress_events: 0,
}
```

The `ShardStats` struct contains the number of events for each "table" from the execution of the program, including precompile tables. In the example above, the `nb_keccak_permute_events` field is `2916`, indicating that the precompile for the Keccak permutation was used. 