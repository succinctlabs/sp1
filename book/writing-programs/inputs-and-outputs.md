# Inputs and Outputs

In real world applications of zero-knowledge proofs, you almost always want to verify your proof in the context of some inputs and outputs. For example:

- **Rollups**: Given a list of transactions, prove the new state of the blockchain.
- **Coprocessors**: Given a block header, prove the historical state of some storage slot inside a smart contract.
- **Attested Images**: Given a signed image, prove that you made a restricted set of image transformations.

In this section, we cover how you pass inputs and outputs to the zkVM and create new types that support serialization.

## Reading Data

Data that is read is not public to the verifier by default. Use the `sp1_zkvm::io::read::<T>` method:

```rust,noplayground
let a = sp1_zkvm::io::read::<u32>();
let b = sp1_zkvm::io::read::<u64>();
let c = sp1_zkvm::io::read::<String>();
```

Note that `T` must implement the `serde::Serialize` and `serde::Deserialize` trait. If you want to read bytes directly, you can also use the `sp1_zkvm::io::read_vec` method.

```rust,noplayground
let my_vec = sp1_zkvm::io::read_vec();
```

## Committing Data

Committing to data makes the data public to the verifier. Use the `sp1_zkvm::io::commit::<T>` method:

```rust,noplayground
sp1_zkvm::io::commit::<u32>(&a);
sp1_zkvm::io::commit::<u64>(&b);
sp1_zkvm::io::commit::<String>(&c);
```

Note that `T` must implement the `Serialize` and `Deserialize` trait. If you want to write bytes directly, you can also use `sp1_zkvm::io::commit_slice` method:

```rust,noplayground
let mut my_slice = [0_u8; 32];
sp1_zkvm::io::commit_slice(&my_slice);
```

## Creating Serializable Types

Typically, you can implement the `Serialize` and `Deserialize` traits using a simple derive macro on a struct.

```rust,noplayground
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct MyStruct {
    a: u32,
    b: u64,
    c: String
}
```

For more complex usecases, refer to the [Serde docs](https://serde.rs/).

## Example

Here is a basic example of using inputs and outputs with more complex types.

```rust,noplayground
{{#include ../../examples/io/program/src/main.rs}}
```
