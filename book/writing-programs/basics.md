# Writing Programs: Basics 

The easiest way to understand how to write programs for the SP1 zkVM is to look at some examples.

## Example: Fibonacci

This program is from the `examples` [directory](https://github.com/succinctlabs/sp1/tree/main/examples) in the SP1 repo which contains several example programs of varying complexity.

```rust,noplayground
{{#include ../../examples/fibonacci/program/src/main.rs}}
```

As you can see, writing programs is as simple as writing normal Rust. 

After you've written your program, you must compile it to an ELF that the SP1 zkVM can prove. To read more about compiling programs, refer to the section on [Compiling Programs](./compiling.md). To read more about how inputs and outputs work, refer to the section on [Inputs & Outputs](./inputs-and-outputs.md).