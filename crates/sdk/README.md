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

## Example

Here's a simple example of using the SP1 SDK:

```rust
use sp1_sdk::prelude::*;

#[sp1_program]
fn example_program(x: u64, y: u64) -> u64 {
    x + y
}
```

## Components

The SDK includes:

- Program attribute macros
- Precompile interfaces
- Type definitions and traits
- Helper functions and utilities
- Testing frameworks

## Related Components

- `sp1-zkvm`: The underlying VM implementation
- `sp1-core`: Core primitives and utilities
- `sp1-prover`: Proof generation system

For detailed guides and examples, visit the [SP1 documentation](https://docs.succinct.xyz/)
