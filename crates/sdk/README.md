# SP1 SDK

The Software Development Kit (SDK) for building zero-knowledge applications with SP1.

## Overview

The SP1 SDK provides a high-level interface for developers to write zero-knowledge programs in Rust. It abstracts away the complexity of zero-knowledge proof systems while providing full access to Rust's standard library and ecosystem.

## Features

- Write ZK programs in standard Rust
- Full `std` library support
- Easy-to-use macros and annotations
- Seamless integration with most Rust crates
- Built-in precompiles for common operations

## Usage

Add the SDK to your project's `Cargo.toml`:

```toml
[dependencies]
sp1-sdk = { git = "https://github.com/succinctlabs/sp1.git" }
```
