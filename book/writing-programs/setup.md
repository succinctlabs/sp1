# Writing Programs: Setup

In this section, we will teach you how to setup a self-contained crate which can be compiled as a program that can be executed inside the zkVM.

## Create Project with CLI (Recommended)

The recommended way to setup your first program to prove inside the zkVM is using the method described in [Quickstart](../getting-started/quickstart.md) which will create a program folder.

```bash
cargo prove new <name>
cd program
```

## Manual Project Setup

You can also manually setup a project. First create a new Rust project using `cargo`:

```bash
cargo new program
cd program
```

### Cargo Manifest

Inside this crate, add the `sp1-zkvm` crate as a dependency. Your `Cargo.toml` should look like the following:

```rust,noplayground
[workspace]
[package]
version = "0.1.0"
name = "program"
edition = "2021"

[dependencies]
sp1-zkvm = "1.1.0"
```

The `sp1-zkvm` crate includes necessary utilities for your program, including handling inputs and outputs,
precompiles, patches, and more.

### main.rs

Inside the `src/main.rs` file, you must make sure to include these two lines to ensure that your program properly compiles to a valid SP1 program.

```rust,noplayground
#![no_main]
sp1_zkvm::entrypoint!(main);
```

These two lines of code wrap your main function with some additional logic to ensure that your program compiles correctly with the RISC-V target.
