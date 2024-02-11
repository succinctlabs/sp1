# Inputs and Outputs

In real world applications of zero-knowledge proofs, you almost always want to verify your proof in the context of some inputs and outputs. For example:
- **Rollups**: Given a list of transactions, prove the new state of the blockchain.
- **Coprocessors**: Given a block header, prove the historical state of some storage slot inside a smart contract.
- **Attested Images**: Given a signed image, prove that you made a restricted set of image transformations.

In this section, we cover how you pass inputs and outputs to the zkVM and create new types that support serialization.

## Reading Data

For most usecases, use the `succinct_zkvm::io::read::<T>` method:

```rust,noplayground
let a = succinct_zkvm::io::read::<u32>();
let b = succinct_zkvm::io::read::<u64>();
let c = succinct_zkvm::io::read::<String>();
```

Note that `T` must implement the `Serialize` and `Deserialize` trait. If you want to read bytes directly, you can also use `succinct_zkvm::io::read_slice`.

## Writing Data

For most usecases, use the `succinct_zkvm::io::write::<T>` method:

```rust,noplayground
succinct_zkvm::io::write::<u32>(&a);
succinct_zkvm::io::write::<u64>(&b);
succinct_zkvm::io::write::<String>(&c);
```

Note that `T` must implement the `Serialize` and `Deserialize` trait.  If you want to write bytes directly, you can also use `succinct_zkvm::io::write_slice`.

## Creating Serializable Types

Typically, you can implement the `Serialize` and `Deserialize` traits using a simple derive macro on a struct.
```rust,noplayground
use serde::{Serialize, de::Deserialize};

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
{{#include ../../programs/demo/io/src/main.rs}}
```