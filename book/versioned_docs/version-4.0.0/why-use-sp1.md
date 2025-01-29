# Why use SP1?

## Use-Cases

Zero-knowledge proofs (ZKPs) are a powerful primitive that enable **verifiable computation**. With ZKPs, anyone can verify a cryptographic proof that a program has executed correctly, without needing to trust the prover, re-execute the program or even know the inputs to the program.

Historically, building ZKP systems has been extremely complicated, requiring large teams with specialized cryptography expertise and taking years to go to production. SP1 is a performant, general-purpose zkVM that solves this problem and creates a future where all blockchain infrastructure, including rollups, bridges, coprocessors, and more, utilize ZKPs **via maintainable software written in Rust**.

SP1 is especially powerful in blockchain contexts which rely on verifiable computation. Example applications include:
- [Rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/): SP1 can be used in combination with existing node infrastructure like [Reth](https://github.com/paradigmxyz/reth) to build rollups with ZKP validity proofs or ZK fraud proofs.
- [Coprocessors](https://crypto.mirror.xyz/BFqUfBNVZrqYau3Vz9WJ-BACw5FT3W30iUX3mPlKxtA): SP1 can be used to outsource onchain computation to offchain provers to enable use cases such as large-scale computation over historical state and onchain machine learning, dramatically reducing gas costs. 
- [Light Clients](https://ethereum.org/en/developers/docs/nodes-and-clients/light-clients/): SP1 can be used to build light clients that can verify the state of other chains, facilitating interoperability between different blockchains without relying on any trusted third parties.

SP1 has already been integrated in many of these applications, including but not limited to:

- [SP1 Tendermint](https://github.com/succinctlabs/sp1-tendermint-example): An example of a ZK Tendermint light client on Ethereum powered by SP1.
- [SP1 Reth](https://github.com/succinctlabs/rsp): A performant, type-1 zkEVM written in Rust & SP1 using Reth.
- [SP1 Contract Call](https://github.com/succinctlabs/sp1-contract-call): A lightweight library to generate ZKPs of Ethereum smart contract execution
- and many more!

SP1 is used by protocols in production today:

- [SP1 Blobstream](https://github.com/succinctlabs/sp1-blobstream): A bridge that verifies [Celestia](https://celestia.org/) “data roots” (a commitment to all data blobs posted in a range of Celestia blocks) on Ethereum and other EVM chains.
- [SP1 Vector](https://github.com/succinctlabs/sp1-vector): A bridge that relays [Avail's](https://www.availproject.org/) merkle root to Ethereum and also functions as a token bridge from Avail to Ethereum.


## 100x developer productivity

SP1 enables teams to use ZKPs in production with minimal overhead and fast timelines.

**Maintainable:** With SP1, you can reuse existing Rust crates, like `revm`, `reth`, `tendermint-rs`, `serde` and more, to write your ZKP logic in maintainable, Rust code.

**Go to market faster:** By reusing existing crates and expressing ZKP logic in regular code, SP1 significantly reduces audit surface area and complexity, enabling teams to go to market with ZKPs faster.

## Blazing Fast Performance

SP1 is the fastest zkVM and has blazing fast performance on a variety of realistic blockchain workloads, including light clients and rollups. With SP1, ZKP proving costs are an order of magnitude less than alternative zkVMs or even circuits, making it cost-effective and fast for practical use.

Read more about our benchmarking results [here](https://blog.succinct.xyz/sp1-benchmarks-8-6-24).

## Open Source 

SP1 is 100% open-source (MIT / Apache 2.0) with no code obfuscation and built to be contributor friendly, with all development done in the open. Unlike existing zkVMs whose constraint logic is closed-source and impossible to audit or modify, SP1 is modularly architected and designed to be customizable from day one. This customizability (unique to SP1) allows for users to add “precompiles” to the core zkVM logic that yield substantial performance gains, making SP1’s performance not only SOTA vs. existing zkVMs, but also competitive with circuits in a variety of use-cases.



