# Writing Programs: Basics 

A zero-knowledge proof generally proves that some function `f` when applied to some input `x` produces some output `y` (i.e. `f(x) = y`).
In the context of the Curta zkVM:

- `f` is written in normal rust code.
- `x` are bytes that can be serialized / deserialized into objects
- `y` are bytes that can be serialized / deserialized into objects

To make this more concrete, let's walk through a simple example of writing a Fibonacci program inside the zkVM.

## Fibonacci

This program is from the `programs` directory in the Curta zkVM repo which contains several program examples of varying complexity.

```rust,noplayground
{{#include ../../programs/demo/fibonacci-io/src/main.rs}}
```

As you can see, writing programs is as simple as writing normal Rust. To read more about how inputs and outputs work, refer to the section on [Inputs & Outputs](./inputs-and-outputs.md).