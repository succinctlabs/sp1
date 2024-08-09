# Common Issues

## Bus Error

If you are running a executable that uses the `sp1-sdk` crate, you may encounter a bus error like this:

```txt
zsh: bus error
```

This is fixed by running with the `--release` flag, as the `sp1-sdk` crate only supports release builds as of right now.

## Alloy Errors

If you are using a library that depends on `alloy_sol_types`, and encounter an error like this:

```txt
perhaps two different versions of crate `alloy_sol_types` are being used?
```

This is likely due to two different versions of `alloy_sol_types` being used. To fix this, you can set `default-features` to `false` for the `sp1-sdk` dependency in your `Cargo.toml`.

```toml
[dependencies]
sp1-sdk = { version = "1.1.0", default-features = false }
```

This will configure out the `network` feature which will remove the dependency on `alloy_sol_types` and configure out the `NetworkProver`.

## Rust Version Errors

If you are using a library that has an MSRV (minimum supported rust version) of 1.76.0
or higher, you may encounter an error like this when building your program.

```txt
package `alloy v0.1.1 cannot be built because it requires rustc 1.76 or newer, while the currently active rustc version is 1.75.0-nightly`
```

This is due to the fact that the Succinct Rust toolchain might be built with a lower version than the MSRV of the crates you are using. You can check the version of the Succinct Rust toolchain by running `cargo +succinct --version`. The Succinct Rust toolchain's latest version is 1.79, and you can update to the latest version by running [`sp1up`](../getting-started/install.md).

If that doesn't work (i.e. the MSRV of the crates you are using is still higher than the version of the Succinct Rust toolchain), you can try the following:

- If you're using `cargo prove build` directly, pass the `--ignore-rust-version` flag:

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

## Stack Overflow Errors

If you encounter the following in a script using `sp1-sdk`:

```txt
thread 'main' has overflowed its stack
fatal runtime error: stack overflow
```

```txt
Segmentation fault (core dumped)
```

Re-run your script with `--release`.

Note that the core `sp1-core` library and `sp1-recursion` require being compiled with the `release` profile.

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