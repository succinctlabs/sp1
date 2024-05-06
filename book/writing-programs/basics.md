# Writing Programs: Basics 

A zero-knowledge proof generally proves that some function `f` when applied to some input `x` produces some output `y` (i.e. `f(x) = y`).
In the context of the SP1 zkVM:

- `f` is written in normal Rust code.
- `x` are bytes that can be serialized / deserialized into objects
- `y` are bytes that can be serialized / deserialized into objects

To make this more concrete, let's walk through a simple example of writing a Fibonacci program inside the zkVM.

## Fibonacci

This program is from the `examples` [directory](https://github.com/succinctlabs/sp1/tree/main/examples) in the SP1 repo which contains several example programs of varying complexity.

```rust,noplayground
{{#include ../../examples/fibonacci/program/src/main.rs}}
```

As you can see, writing programs is as simple as writing normal Rust. To read more about how inputs and outputs work, refer to the section on [Inputs & Outputs](./inputs-and-outputs.md).