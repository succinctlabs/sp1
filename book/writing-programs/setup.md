# Writing Programs: Setup

In this section, we will teach you how to setup a self-contained crate which can be compiled as an program that can be executed inside the zkVM.

## CLI (Recommended)

The recommended way to setup your first program to prove inside the zkVM is using the method described in [Quickstart](../getting-started/quickstart.md) which will create a program folder.

```bash
cargo prove new <name>
cd program
```

### Build

To build the program, simply run:

```
cargo prove build
```

This will compile the ELF that can be executed in the zkVM and put the executable in `elf/riscv32im-succinct-zkvm-elf`.

### Build with Docker

Another option is to build your program in a Docker container. This is useful if you are on a platform that does not have prebuilt binaries for the succinct toolchain, or if you are looking to get a reproducible ELF output. To do so, just use the `--docker` flag.

```
cargo prove build --docker
```

## Manual

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

### Build

To build the program, simply run:

```
cargo prove build
```

This will compile the ELF (RISCV binary) that can be executed in the zkVM and put the executable in `elf/riscv32im-succinct-zkvm-elf`.
