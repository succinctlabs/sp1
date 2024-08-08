# Cycle Tracking

When writing a program, it is useful to know how many RISC-V cycles a portion of the program takes to identify potential performance bottlenecks. SP1 provides a way to track the number of cycles spent in a portion of the program.

## Tracking Cycles with Annotations

To track the number of cycles spent in a portion of the program, you can either put `println!("cycle-tracker-start: block name")` + `println!("cycle-tracker-end: block name")` statements (block name must be same between start and end) around the portion of your program you want to profile or use the `#[sp1_derive::cycle_tracker]` macro on a function. An example is shown below:

```rust,noplayground
{{#include ../../examples/cycle-tracking/program/bin/normal.rs}}
```

Note that to use the macro, you must add the `sp1-derive` crate to your dependencies for your program.

```toml
[dependencies]
sp1-derive = "1.1.0"
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

### Get Tracked Cycle Counts
To include tracked cycle counts in the `ExecutionReport` when using `ProverClient::execute`, use the following annotations:

```rust,noplayground
fn main() {
  println!("cycle-tracker-report-start: block name");
  // ...
  println!("cycle-tracker-report-end: block name");
}
```

This will log the cycle count for `block name` and include it in the `ExecutionReport` in the `cycle_tracker` map.

## Tracking Cycles with Tracing

The `cycle-tracker` annotation is a convenient way to track cycles for specific sections of code. However, sometimes it can also be useful to track what functions are taking the most cycles across the entire program, without having to annotate every function individually.

First, we need to generate a trace file of the program counter at each cycle while the program is executing. This can be done by simply setting the `TRACE_FILE` environment variable with the path of the file you want to write the trace to. For example, you can run the following command in the `script` directory for any example program:

```bash
TRACE_FILE=trace.log RUST_LOG=info cargo run --release
```

When the `TRACE_FILE` environment variable is set, as SP1's RISC-V runtime is executing, it will write a log of the program counter to the file specified by `TRACE_FILE`. 


Next, we can use the `cargo prove` CLI with the `trace` command to analyze the trace file and generate a table of instruction counts. This can be done with the following command:

```bash
cargo prove trace --elf <path_to_program_elf> --trace <path_to_trace_file>
```

The `trace` command will generate a table of instruction counts, sorted by the number of cycles spent in each function. The output will look something like this:

```
  [00:00:00] [########################################] 17053/17053 (0s)

Total instructions in trace: 17053


 Instruction counts considering call graph
+----------------------------------------+-------------------+
| Function Name                          | Instruction Count |
| __start                                | 17045             |
| main                                   | 12492             |
| sp1_zkvm::syscalls::halt::syscall_halt | 4445              |
| sha2::sha256::compress256              | 4072              |
| sp1_lib::io::commit                    | 258               |
| sp1_lib::io::SyscallWriter::write      | 255               |
| syscall_write                          | 195               |
| memcpy                                 | 176               |
| memset                                 | 109               |
| sp1_lib::io::read_vec                  | 71                |
| __rust_alloc                           | 29                |
| sp1_zkvm::heap::SimpleAlloc::alloc     | 22                |
| syscall_hint_len                       | 3                 |
| syscall_hint_read                      | 2                 |
+----------------------------------------+-------------------+


 Instruction counts ignoring call graph
+----------------------------------------+-------------------+
| Function Name                          | Instruction Count |
| main                                   | 12075             |
| sha2::sha256::compress256              | 4073              |
| sp1_zkvm::syscalls::halt::syscall_halt | 219               |
| memcpy                                 | 180               |
| syscall_write                          | 123               |
| memset                                 | 111               |
| sp1_lib::io::commit                    | 88                |
| sp1_lib::io::SyscallWriter::write      | 60                |
| __start                                | 45                |
| sp1_lib::io::read_vec                  | 35                |
| sp1_zkvm::heap::SimpleAlloc::alloc     | 23                |
| anonymous                              | 7                 |
| __rust_alloc                           | 7                 |
| syscall_hint_len                       | 4                 |
| syscall_hint_read                      | 3                 |
+----------------------------------------+-------------------+
```
