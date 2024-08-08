# SP1

![SP1](./assets/sp1.png)

SP1 is the fastest, most-feature complete zero-knowledge virtual machine (zkVM) that can prove the execution of arbitrary Rust (or any LLVM-compiled language) programs. SP1 makes ZK accessible to *any developer*, by making it easy to write ZKP programs in normal Rust code.

**[Install](https://succinctlabs.github.io/sp1/getting-started/install.html)**
| [Docs](https://succinctlabs.github.io/sp1)
| [Examples](https://github.com/succinctlabs/sp1/tree/main/examples)
| [Telegram Chat](https://t.me/+AzG4ws-kD24yMGYx)

## Getting Started 

Today, developers can write programs, including complex, large programs like a ZK Tendermint light client or type-1 zkEVM using Reth, in Rust (with std support), generate proofs and verify them. Most Rust crates should be supported and can be used seamlessly by your program. Example programs can be found in the [examples](https://github.com/succinctlabs/sp1/tree/main/examples) folder.

To get started, make sure you have [Rust](https://www.rust-lang.org/tools/install) installed. Then follow the [installation](https://succinctlabs.github.io/sp1/getting-started/install.html) guide in the SP1 book and read the [getting started](https://succinctlabs.github.io/sp1/getting-started/quickstart.html) section.

## Security

SP1 has undergone audits from [Veridise](https://www.veridise.com/), [Cantina](https://cantina.xyz/),
and [KALOS](https://kalos.xyz/) and is recommended for production use. The audit reports are available [here](./audits).


## For Contributors

Open-source is a core part of SP1's ethos and key to its advantages. We wish to cultivate a vibrant community of open-source contributors that span individuals, teams and geographies. If you want to contribute, or follow along with contributor discussion, you can use our main Telegram to chat with us. Our contributor guidelines can be found in [CONTRIBUTING.md](./CONTRIBUTING.md). A quick overview of development tips can be found in [DEVELOPMENT.md](./DEVELOPMENT.md).

We are always looking for contributors interested in tasks big and small, including minor chores across the codebase, optimizing performance, adding precompiles for commonly used cryptographic operations, adding documentation, creating new example programs and more. Please reach out in the Telegram chat if interested!

