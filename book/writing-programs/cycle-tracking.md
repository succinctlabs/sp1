# Cycle Tracking

When writing a program, it is useful to know how many RISC-V cycles a portion of the program takes to identify potential performance bottlenecks. SP1 provides a way to track the number of cycles spent in a portion of the program.

## Tracking Cycles

To track the number of cycles spent in a portion of the program, you can either put `println!("cycle-tracker-start: block name")` + `println!("cycle-tracker-end: block name")` statements (block name must be same between start and end) around the portion of your program you want to profile or use the `#[sp1_derive::cycle_tracker]` macro on a function. An example is shown below:

```rust,noplayground
{{#include ../../examples/cycle-tracking/program/src/main.rs}}
```

Note that to use the macro, you must add the `sp1-derive` crate to your dependencies for your program.

```toml
[dependencies]
sp1-derive = { git = "https://github.com/succinctlabs/sp1.git" }
```

In the script for proof generation, setup the logger with `utils::setup_logger()` and run the script with `RUST_LOG=info cargo run --release`. You should see the following output:

```
$ RUST_LOG=info cargo run --release
    Finished release [optimized] target(s) in 0.21s
     Running `target/release/cycle-tracking-script`
2024-03-13T02:03:40.567500Z  INFO execute: loading memory image
2024-03-13T02:03:40.567751Z  INFO execute: starting execution
2024-03-13T02:03:40.567760Z  INFO execute: clk = 0 pc = 0x2013b8    
2024-03-13T02:03:40.567822Z  INFO execute: ┌╴setup    
2024-03-13T02:03:40.568095Z  INFO execute: └╴4,398 cycles    
2024-03-13T02:03:40.568122Z  INFO execute: ┌╴main-body    
2024-03-13T02:03:40.568149Z  INFO execute: │ ┌╴expensive_function    
2024-03-13T02:03:40.568250Z  INFO execute: │ └╴1,368 cycles    
stdout: result: 5561
2024-03-13T02:03:40.568373Z  INFO execute: │ ┌╴expensive_function    
2024-03-13T02:03:40.568470Z  INFO execute: │ └╴1,368 cycles    
stdout: result: 2940
2024-03-13T02:03:40.568556Z  INFO execute: └╴5,766 cycles    
2024-03-13T02:03:40.568566Z  INFO execute: finished execution clk = 11127 pc = 0x0
2024-03-13T02:03:40.569251Z  INFO execute: close time.busy=1.78ms time.idle=21.1µs
```

Note that we elegantly handle nested cycle tracking, as you can see above.
