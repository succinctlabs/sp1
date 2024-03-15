# Advanced Usage

## Execution Only

We recommend that during development of large programs (> 1 million cycles) that you do not generate proofs each time.
Instead, you should have your script only execute the program with the RISC-V runtime and read `stdout`. Here is an example:

```rust,noplayground
use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};

// The ELF file with the RISC-V bytecode of the program from above.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let mut stdin = SP1Stdin::new(); 
    let n = 5000u32;
    stdin.write(&n); 
    let mut stdout = SP1Prover::execute(ELF, stdin).expect("execution failed");
    let a = stdout.read::<u32>(); 
    let b = stdout.read::<u32>();

    // Print the program's outputs in our script.
    println!("a: {}", a);
    println!("b: {}", b);
    println!("succesfully executed the program!")
}
```

If execution of your program succeeds, then proof generation should succeed as well! (Unless there is a bug in our zkVM implementation.)


## Performance

For maximal performance, you should run proof generation with the following command and vary your `shard_size` depending on your program's number of cycles.

```rust,noplayground
SHARD_SIZE=4194304 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```

You can also use the `SAVE_DISK_THRESHOLD` env variable to control whether shards are saved to disk or not.
This is useful for controlling memory usage.

```rust,noplayground
SAVE_DISK_THRESHOLD=64 SHARD_SIZE=2097152 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```

#### Blake3 on ARM machines

Blake3 on ARM machines requires using the `neon` feature of `sp1-core`. For examples in the sp1-core repo, you can use:

```rust,noplayground
SHARD_SIZE=2097152 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release --features neon
```

Otherwise, make sure to include the "neon" feature when importing `sp1-zkvm` in your `Cargo.toml`:

```toml,noplayground
sp1-core = { git = "https://github.com/succinctlabs/sp1.git", features = [ "neon" ] }
```

## Logging and Tracing Information

You can either use `utils::setup_logger()` or `utils::setup_tracer()` to enable logging and tracing information respectively. You should only use one or the other of these functions.

**Tracing:**

Tracing will show more detailed timing information. 

```rust,noplayground
utils::setup_tracer();
```

You must run your command with:
```bash
RUST_TRACER=info cargo run --release
```

**Logging:**
```rust,noplayground
utils::setup_logger();
```

You must run your command with:
```bash
RUST_LOG=info cargo run --release
```