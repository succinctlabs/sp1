# Writing Programs: Setup

In this section, we will teach you how to setup a self-contained crate which can be compiled as a program that can be executed inside the zkVM.

## Create Project with CLI (Recommended)

The recommended way to setup your first program to prove inside the zkVM is using the method described in [Quickstart](../getting-started/quickstart.md) which will create a program folder.

```bash
cargo prove new <name>
cd program
```

## Build with CLI (Development)

> WARNING: This may not generate a reproducible ELF which is necessary for verifying that your binary corresponds to given source code.
>
> Use the [reproducible build system](#build-with-docker-production) for production builds.

To build the program while in development, simply run:

```bash
cargo prove build
```

This will compile the ELF that can be executed in the zkVM and put the executable in `elf/riscv32im-succinct-zkvm-elf`.

## Build with Docker (Production)

For production builds of programs, you can build your program inside a Docker container which will generate a **reproducible ELF** on all platforms. To do so, just use the `--docker` flag and the `--tag` flag with the release version you want to use. For example:

```bash
cargo prove build --docker --tag v1.0.5-testnet
```

To verify that your build is reproducible, you can compute the SHA-512 hash of the ELF on different platforms and systems with:

```bash
$ shasum -a 512 elf/riscv32im-succinct-zkvm-elf
f9afb8caaef10de9a8aad484c4dd3bfa54ba7218f3fc245a20e8a03ed40b38c617e175328515968aecbd3c38c47b2ca034a99e6dbc928512894f20105b03a203
```

## Manual Project Setup

You can also manually setup a project. First create a new cargo project:

```bash
cargo new program
cd program
```

### Cargo Manifest

Inside this crate, add the `sp1-zkvm` crate as a dependency. Your `Cargo.toml` should look like as follows:

```rust,noplayground
[workspace]
[package]
version = "0.1.0"
name = "program"
edition = "2021"

[dependencies]
sp1-zkvm = { git = "https://github.com/succinctlabs/sp1.git" }
```

The `sp1-zkvm` crate includes necessary utilities for your program, including handling inputs and outputs,
precompiles, patches, and more.

### main.rs

Inside the `src/main.rs` file, you must make sure to include these two lines to ensure that the crate
properly compiles.

```rust,noplayground
#![no_main]
sp1_zkvm::entrypoint!(main);
```

These two lines of code wrap your main function with some additional logic to ensure that your program compiles correctly with the RISCV target.
