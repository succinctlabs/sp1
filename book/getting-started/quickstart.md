# Quickstart

In this section, we will show you how to create a simple Fibonacci program using the SP1 zkVM.

## Create an SP1 Project

### Option 1: Cargo Prove New CLI (Recommended)

You can use the `cargo prove` CLI to create a new project using the `cargo prove new <--bare|--evm> <name>` command. The `--bare` option sets up a basic SP1 project for standalone zkVM programs, while `--evm` adds additional components including Solidity contracts for on-chain proof verification.

This command will create a new folder in your current directory which includes solidity smart contracts for onchain integration.

```bash
cargo prove new --evm fibonacci
cd fibonacci
```

### Option 2: Project Template (Solidity Contracts for Onchain Verification)

If you want to use SP1 to generate proofs that will eventually be verified on an EVM chain, you should use the [SP1 project template](https://github.com/succinctlabs/sp1-project-template/tree/main). This Github template is scaffolded with a SP1 program, a script to generate proofs, and also a contracts folder that contains a Solidity contract that can verify SP1 proofs on any EVM chain.

Either fork the project template repository or clone it:

```bash
git clone https://github.com/succinctlabs/sp1-project-template.git
```

### Project Overview

Your new project will have the following structure (ignoring the `contracts` folder, if you are using the project template):

```
.
├── program
│   ├── Cargo.lock
│   ├── Cargo.toml
│   ├── elf
│   │   └── riscv32im-succinct-zkvm-elf
│   └── src
│       └── main.rs
├── rust-toolchain
└── script
    ├── Cargo.lock
    ├── Cargo.toml
    ├── build.rs
    └── src
        └── bin
            ├── prove.rs
            └── vkey.rs

6 directories, 4 files
```

There are 2 directories (each a crate) in the project: 
- `program`: the source code that will be proven inside the zkVM.
- `script`: code that contains proof generation and verification code.

**We recommend you install the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) extension.**
Note that if you use `cargo prove new` inside a monorepo, you will need to add the manifest file to `rust-analyzer.linkedProjects` to get full IDE support.

## Build

Before we can run the program inside the zkVM, it must be compiled to a RISC-V executable using the `succinct` Rust toolchain. This is called an [ELF (Executable and Linkable Format)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format). To compile the program, you can run the following command:

```
cd program && cargo prove build
```

which will output the compiled ELF to the file `program/elf/riscv32im-succinct-zkvm-elf`. 

Note: the `build.rs` file in the `script` directory will use run the above command automatically to build the ELF, meaning you don't have to manually run `cargo prove build` every time you make a change to the program!

## Execute

To test your program, you can first execute your program without generating a proof. In general this is helpful for iterating on your program and verifying that it is correct. 

```bash
cd ../script
RUST_LOG=info cargo run --release -- --execute
```

## Prove

When you are ready to generate a proof, you should run the script with the `--prove` flag that will generate a proof.

```bash
cd ../script
RUST_LOG=info cargo run --release -- --prove
```

The output should show something like this:
```
n: 20
2024-07-23T17:07:07.874856Z  INFO prove_core:collect_checkpoints: clk = 0 pc = 0x2017e8
2024-07-23T17:07:07.876264Z  INFO prove_core:collect_checkpoints: close time.busy=2.00ms time.idle=1.50µs
2024-07-23T17:07:07.913304Z  INFO prove_core:shard: close time.busy=32.2ms time.idle=791ns
2024-07-23T17:07:10.724280Z  INFO prove_core:commit: close time.busy=2.81s time.idle=1.25µs
2024-07-23T17:07:10.725923Z  INFO prove_core:prove_checkpoint: clk = 0 pc = 0x2017e8     num=0
2024-07-23T17:07:10.729130Z  INFO prove_core:prove_checkpoint: close time.busy=3.68ms time.idle=1.17µs num=0
2024-07-23T17:07:14.648146Z  INFO prove_core: execution report (totals): total_cycles=9329, total_syscall_cycles=20
2024-07-23T17:07:14.648180Z  INFO prove_core: execution report (opcode counts):
2024-07-23T17:07:14.648197Z  INFO prove_core:   1948 add
...
2024-07-23T17:07:14.648277Z  INFO prove_core: execution report (syscall counts):
2024-07-23T17:07:14.648408Z  INFO prove_core:   8 commit
...
2024-07-23T17:07:14.648858Z  INFO prove_core: summary: cycles=9329, e2e=9.193968459, khz=1014.69, proofSize=1419780
2024-07-23T17:07:14.653193Z  INFO prove_core: close time.busy=9.20s time.idle=12.2µs
Successfully generated proof!
fib(n): 10946
```

The program by default is quite small, so proof generation will only take a few seconds locally. After it generates, the proof will be verified for correctness. 

**Note:** When benchmarking proof generation times locally, it is important to note that there is a fixed overhead for proving, which means that the proof generation time for programs with a small number of cycles is not representative of the performance of larger programs (which often have better performance characteristics as the overhead is amortized across many cycles).

## Recommended Workflow

Please see the [Recommended Workflow](../generating-proofs/recommended-workflow.md) section for more details on how to develop your SP1 program and generate proofs.

We *strongly recommend* that developers who want to use SP1 for non-trivial programs generate proofs on the beta version of our [Prover Network](../generating-proofs/prover-network.md). The prover network generates SP1 proofs across multiple machines, reducing latency and also runs SP1 on optimized hardware instances that result in faster + cheaper proof generation times.

We recommend that for any production benchmarking, you use the prover network to estimate latency and costs of proof generation. We also would love to chat with your team directly to help you get started with the prover network--please fill out this [form](https://partner.succinct.xyz/).

