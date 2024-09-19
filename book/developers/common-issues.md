# Common Issues

## `cargo prove build` fails to compile `getrandom`

If you are running into an error like this:

```txt
[sp1]     Compiling getrandom v0.2.10
[sp1]  error: target is not supported, for more information see: https://docs.rs/getrandom/#unsupported-targets
[sp1]     --> /Users/umaroy/.cargo/registry/src/index.crates.io-6f17d22bba15001f/getrandom-0.2.10/src/lib.rs:290:9
[sp1]      |
[sp1]  290 | /         compile_error!("target is not supported, for more information see: \
[sp1]  291 | |                         https://docs.rs/getrandom/#unsupported-targets");
[sp1]      | |________________________________________________________________________^
[sp1]
[sp1]  error[E0433]: failed to resolve: use of undeclared crate or module `imp`
[sp1]     --> /Users/umaroy/.cargo/registry/src/index.crates.io-6f17d22bba15001f/getrandom-0.2.10/src/lib.rs:341:9
[sp1]      |
[sp1]  341 |         imp::getrandom_inner(dest)?;
[sp1]      |         ^^^ use of undeclared crate or module `imp`
[sp1]
[sp1]  For more information about this error, try `rustc --explain E0433`.
[sp1]  error: could not compile `getrandom` (lib) due to 2 previous errors
```

The first solution is to import `sp1-zkvm` in your crate, which will ensure that the `getrandom` dependency is [shimmed correctly](https://github.com/succinctlabs/sp1/blob/dev/crates/zkvm/entrypoint/src/lib.rs#L81).

Otherwise, to fix this manually, you can add the following code that will implement a custom `getrandom` function that always returns an error and will compile within SP1:

```
#[cfg(target_os = "zkvm")]
mod random_shim {
    use getrandom::register_custom_getrandom;

    register_custom_getrandom!(return_err);

    pub fn return_err(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNEXPECTED)
    }
}
```

Make sure to import `getrandom` in your `Cargo.toml` with the `custom` feature:

```
getrandom = { version = "0.2", features = ["custom"] }
```

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

If you are using `alloy` or another library that has an MSRV (minimum supported rust version) of 1.76.0
or higher, you may encounter an error like this when building your program.

```txt
package `alloy v0.1.1 cannot be built because it requires rustc 1.76 or newer, while the currently active rustc version is 1.75.0-nightly`
```

This is due to the fact that the Succinct Rust toolchain might be built with a lower version than the MSRV of the crates you are using. You can check the version of the Succinct Rust toolchain by running `cargo +succinct --version`. If we have released a more recent version of the Succinct Rust toolchain, you can update it by running `sp1up` again to update the toolchain and CLI to the latest version.

You can also fix this issue with the following:

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
