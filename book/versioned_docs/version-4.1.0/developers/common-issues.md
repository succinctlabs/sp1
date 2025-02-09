# Common Issues

## Rust Version Errors

If you are using a library that has an MSRV specified, you may encounter an error like this when building your program.

```txt
package `alloy cannot be built because it requires rustc 1.83 or newer, while the currently active rustc version is 1.82.0`
```

This is due to the fact that your current Succinct Rust toolchain has been built with a lower version than the MSRV of the crates you are using.

You can check the version of your local Succinct Rust toolchain by running `cargo +succinct --version`. The latest release of the Succinct Rust toolchain is **1.82**. You can update to the latest version by running [`sp1up`](../getting-started/install.md).

```shell
% sp1up
% cargo +succinct --version
cargo 1.82.0-dev (8f40fc59f 2024-08-21)
```

A Succinct Rust toolchain with version **1.82** should work for all crates that have an MSRV of **1.82** or lower.

If the MSRV of your crate is higher than **1.82**, try the following:

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
sp1-sdk = { version = "4.0.0", default-features = false }
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

## Failed to run LLVM passes: unknown pass name 'loweratomic'

The Rust compiler had breaking changes to its names of available options between 1.81 and 1.82.

```bash
  [sp1]     Compiling proc-macro2 v1.0.93
  [sp1]     Compiling unicode-ident v1.0.14
  [sp1]     Compiling quote v1.0.38
  [sp1]     Compiling syn v2.0.96
  [sp1]     Compiling serde_derive v1.0.217
  [sp1]     Compiling serde v1.0.217
  [sp1]  error: failed to run LLVM passes: unknown pass name 'loweratomic'
```

This message indicates that you're trying to use `sp1-build` < `4.0.0` with the 1.82 toolchain,
`sp1-build` versions >= 4.0.0 have support for the 1.82 and 1.81 toolchains.

## Slow `ProverClient` Initialization

You may encounter slow `ProverClient` initialization times as it loads necessary proving parameters and sets up the environment. It is recommended to initialize the `ProverClient` once and reuse it for subsequent proving operations. You can wrap the `ProverClient` in an `Arc` to share it across tasks.
