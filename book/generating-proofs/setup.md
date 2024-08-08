# Generating Proofs: Setup

In this section, we will teach you how to setup a self-contained crate which can generate proofs of programs that have been compiled with the SP1 toolchain inside the SP1 zkVM, using the `sp1-sdk` crate.

## CLI (Recommended)

The recommended way to setup your first program to prove inside the zkVM is using the method described in [Quickstart](../getting-started/quickstart.md) which will create a script folder.

```bash
cargo prove new <name>
cd script
```

## Manual

You can also manually setup a project. First create a new cargo project:

```bash
cargo new script
cd script
```

#### Cargo Manifest

Inside this crate, add the `sp1-sdk` crate as a dependency. Your `Cargo.toml` should look like as follows:

```rust,noplayground
[workspace]
[package]
version = "0.1.0"
name = "script"
edition = "2021"

[dependencies]
sp1-sdk = "1.1.0"
```

The `sp1-sdk` crate includes the necessary utilities to generate, save, and verify proofs.
