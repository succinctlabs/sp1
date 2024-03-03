# Cycle Tracking

When writing a program, it is useful to know how many RISC-V cycles a portion of the program takes to identify potential performance bottlenecks. SP1 provides a way to track the number of cycles spent in a portion of the program.

## Tracking Cycles

To track the number of cycles spent in a portion of the program, you can either use a `println!("cycle-tracker-{start,end}:")` statement that wraps the portion of your program you want to profile or use the `#[sp1_derive::cycle_tracker]` macro on a function. An example is shown below:


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
    Finished release [optimized] target(s) in 0.61s
    Running `target/release/cycle-tracking-script`
2024-03-02T19:47:07.490898Z  INFO runtime.run(...):load memory: close time.busy=280µs time.idle=3.92µs
2024-03-02T19:47:07.491085Z  INFO runtime.run(...): ┌╴setup
2024-03-02T19:47:07.491531Z  INFO runtime.run(...): └╴4,398 cycles
2024-03-02T19:47:07.491570Z  INFO runtime.run(...): ┌╴main-body
2024-03-02T19:47:07.491607Z  INFO runtime.run(...): │ ┌╴expensive_function
2024-03-02T19:47:07.491886Z  INFO runtime.run(...): │ └╴1,368 cycles
2024-03-02T19:47:07.492045Z  INFO runtime.run(...): stdout: result: 5561
2024-03-02T19:47:07.492112Z  INFO runtime.run(...): │ ┌╴expensive_function
2024-03-02T19:47:07.492358Z  INFO runtime.run(...): │ └╴1,368 cycles
2024-03-02T19:47:07.492501Z  INFO runtime.run(...): stdout: result: 2940
2024-03-02T19:47:07.492560Z  INFO runtime.run(...): └╴5,766 cycles
2024-03-02T19:47:07.494178Z  INFO runtime.run(...):postprocess: close time.busy=1.57ms time.idle=625ns
```

Note that we elegantly handle nested cycle tracking, as you can see above.

