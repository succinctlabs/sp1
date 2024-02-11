# Writing Programs: Basics 

A zero-knowledge proof generally proves that some function `f` when applied to some input `x` produces some output `y` (i.e. `f(x) = y`).
In the context of the Curta zkVM:

- `f` is written in normal rust code.
- `x` are bytes that can be serialized / deserialized into objects
- `y` are bytes that can be serialized / deserialized into objects

To make this more concrete, let's walk through a simple example of writing a Fibonacci program inside the zkVM.

## Fibonacci

This program is from the `programs` directory in the Curta zkVM repo which contains several program examples of varying complexity.

```rust
{{#include ../../../programs/demo/fibonacci-io/src/main.rs}}
```

As you can see, writing programs is as simple as writing normal Rust. To read more about how inputs and outputs work, refer to the section on [Inputs & Outputs](./inputs-and-outputs.md).

<!-- ## Annotated Proof Generation

We annotate the example script from the [Hello World Program](../hello-world.mdx) tutorial to illustrate how proof generation works.


```rust
use succinct_core::{SuccinctProver, SuccinctStdin, SuccinctVerifier};

// The ELF file with the RISC-V bytecode of the program from above.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Create a new SuccinctStdin object. This is used for providing inputs to the program.
    let mut stdin = SuccinctStdin::new(); 
    let n = 5000u32; // The program computes the `n`-th Fibonacci number.
    // Write to the stdin. You can write any type that implements `serde::Serialize`.
    // You can write multiple values to the stdin. 
    // Every write to stdin should correspond to a `succinct_zkvm::io::read::<T>()` 
    // in the program with the same type `T`.
    stdin.write(&n); 
    // The SuccinctProver will run the program with the provided input and generate a proof locally.
    // The proof object contains both the proof and the stdin and stdout of the program.
    let mut proof = SuccinctProver::prove(ELF, stdin).expect("proving failed");

    // Read output of the program. You can read any type that implements `serde::Deserialize`.
    // Every read from stdout should correspond to a `succinct_zkvm::io::write(&T)`
    // in the program with the same type `T`.
    let a = proof.stdout.read::<u32>(); 
    let b = proof.stdout.read::<u32>();

    // Print the program's outputs in our script.
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof.
    // This verification function will verify that a valid proof exists
    // for the provided program (specified by the ELF) such that when the 
    // program is run with the provided inputs, it produces the provided 
    // outputs (specified by the proof object).
    SuccinctVerifier::verify(ELF, &proof).expect("verification failed");

    // Save proof to a file.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
``` -->