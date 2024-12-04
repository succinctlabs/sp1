# Common Issues

## Rust Version Errors

If you are using a library that has an MSRV specified, you may encounter an error like this when building your program.

```txt
package `alloy v0.1.1 cannot be built because it requires rustc 1.76 or newer, while the currently active rustc version is 1.75.0-nightly`
```

This is due to the fact that your current Succinct Rust toolchain has been built with a lower version than the MSRV of the crates you are using. 

You can check the version of your local Succinct Rust toolchain by running `cargo +succinct --version`. The latest release of the Succinct Rust toolchain is **1.81**. You can update to the latest version by running [`sp1up`](../getting-started/install.md).

```shell
% sp1up
% cargo +succinct --version
cargo 1.81.0-dev (2dbb1af80 2024-08-20)
```

A Succinct Rust toolchain with version **1.81** should work for all crates that have an MSRV of **1.81** or lower.

If the MSRV of your crate is higher than **1.81**, try the following:

- If using `cargo prove build` directly, pass the `--ignore-rust-version` flag:

  ```bash
  cargo prove build --ignore-rust-version
  ```

- If using `build_program` in an `build.rs` file with the `sp1-build` crate, set `ignore_rust_version` to true inside the `BuildArgs` struct and use
  `build_program_with_args`:

  ```rust
  let args = BuildArgs {
      ignore_rust_version: true,
      ..Default::default()
  };
  build_program_with_args("path/to/program", args);
  ```

## `alloy_sol_types` Errors

If you are using a library that depends on `alloy_sol_types`, and encounter an error like this:

```txt
perhaps two different versions of crate `alloy_sol_types` are being used?
```

This is likely due to two different versions of `alloy_sol_types` being used. To fix this, you can set `default-features` to `false` for the `sp1-sdk` dependency in your `Cargo.toml`.

```toml
[dependencies]
sp1-sdk = { version = "2.0.0", default-features = false }
```

This will configure out the `network` feature which will remove the dependency on `alloy_sol_types` and configure out the `NetworkProver`.

## Stack Overflow Errors + Bus Errors

If you encounter any of the following errors in a script using `sp1-sdk`:

```shell
# Stack Overflow Error
thread 'main' has overflowed its stack
fatal runtime error: stack overflow

# Bus Error
zsh: bus error

# Segmentation Fault
Segmentation fault (core dumped)
```

Run your script with the `--release` flag. SP1 currently only supports release builds. This is because
the `sp1-core` library and `sp1-recursion` require being compiled with the `release` profile.

## C Binding Errors

If you are building a program that uses C bindings or has dependencies that use C bindings, you may encounter the following errors:

```txt
cc did not execute successfully
```

```txt
Failed to find tool. Is `riscv32-unknown-elf-gcc` installed?
```

To resolve this, re-install sp1 with the `--c-toolchain` flag:

```bash
sp1up --c-toolchain
```

This will install the C++ toolchain for RISC-V and set the `CC_riscv32im_succinct_zkvm_elf` environment
variable to the path of the installed `riscv32-unknown-elf-gcc` binary. You can also use your own
C++ toolchain be setting this variable manually:

```bash
export CC_riscv32im_succinct_zkvm_elf=/path/to/toolchain
```

## Compilation Errors with [`sp1-lib::syscall_verify_sp1_proof`](https://docs.rs/sp1-lib/latest/sp1_lib/fn.syscall_verify_sp1_proof.html)

If you are using the [`sp1-lib::syscall_verify_sp1_proof`](https://docs.rs/sp1-lib/latest/sp1_lib/fn.syscall_verify_sp1_proof.html) function, you may encounter compilation errors when building your program.

```bash
  [sp1]    = note: rust-lld: error: undefined symbol: syscall_verify_sp1_proof
  [sp1]            >>> referenced by sp1_lib.b593533d149f0f6e-cgu.0
  [sp1]            >>>               sp1_lib-8f5deb4c47d01871.sp1_lib.b593533d149f0f6e-cgu.0.rcgu.o:(sp1_lib::verify::verify_sp1_proof::h5c1bb38f11b3fe71) in ...
  [sp1]
  [sp1]
  [sp1]  error: could not compile `package-name` (bin "package-name") due to 1 previous error
```

To resolve this, ensure that you're importing both `sp1-lib` and `sp1-zkvm` with the verify feature enabled.

```toml
[dependencies]
sp1-lib = { version = "<VERSION>", features = ["verify"] }
sp1-zkvm = { version = "<VERSION>", features = ["verify"] }
```

## `sp1-sdk` `rc` Version Semver Errors

When using release candidate (RC) versions of `sp1-sdk` (such as `3.0.0-rc1`), you might face compilation errors if you upgrade to a newer RC version (like `3.0.0-rc4`) and then try to downgrade back to an earlier RC version (such as `3.0.0-rc1`).

This issue arises because some RC releases introduce breaking changes that aren't reflected in their version numbers according to Semantic Versioning (SemVer) rules. To fix this, you need to explicitly downgrade all related crates in your `Cargo.lock` file to match the desired RC version.

To start, verify that the `sp1-sdk` version in your `Cargo.lock` file differs from the version specified in your `Cargo.toml` file:

```shell
% cargo tree -i sp1-sdk
sp1-sdk v3.0.0-rc4 (/Users/sp1/crates/sdk)
├── sp1-cli v3.0.0-rc4 (/Users/sp1/crates/cli)
├── sp1-eval v3.0.0-rc4 (/Users/sp1/crates/eval)
└── sp1-perf v3.0.0-rc4 (/Users/sp1/crates/perf)
```

After confirming the version of `sp1-sdk` in your lockfile, you can downgrade to a specific RC version using the following command. Replace `3.0.0-rc1` with the desired version number:

```shell
%  cargo update -p sp1-build -p sp1-sdk -p sp1-recursion-derive -p sp1-recursion-gnark-ffi -p sp1-zkvm --precise 3.0.0-rc1
```

This command will update the `Cargo.lock` file to specify the lower RC version, resolving any version conflicts and allowing you to continue development.
