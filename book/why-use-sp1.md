# Why use SP1?

Zero-knowledge proofs (ZKPs) are a powerful primitive that enable developers to outsource verifiable computation to provers. But ZKP adoption has been held back because it is “moon math”, requiring specialized knowledge in obscure ZKP frameworks and hard to maintain one-off deployments. 

Performant, general-purpose zkVMs, like SP1, will obsolete the current paradigm of specialized teams hand rolling their own custom ZK stack and create a future where all blockchain infrastructure, including rollups, bridges, coprocessors, and more, utilize ZKPs **via maintainable software written in Rust (or other LLVM-compiled languages)**.

SP1 is especially powerful in blockchain contexts which rely on verifiable computation. Example applications include:
- [Rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/): SP1 can be used in combination with existing node infrastructure like [Reth](https://github.com/paradigmxyz/reth) to build rollups with fraud proofs based on zero-knowledge proofs.
- [Coprocessors](https://crypto.mirror.xyz/BFqUfBNVZrqYau3Vz9WJ-BACw5FT3W30iUX3mPlKxtA): SP1 can be used to outsource onchain computation to offchain provers to enable use cases such as accessing historical state and onchain machine learning, dramatically reducing gas costs. 
- [Light Clients](https://ethereum.org/en/developers/docs/nodes-and-clients/light-clients/): SP1 can be used to build light clients that can verify the state of other chains, facilitating interoperability between different blockchains without relying on any trusted third parties.

SP1 has already been integrated in many of these applications, including but not limited to:

- [SP1 Reth](https://github.com/succinctlabs/sp1-reth): A performant, type-1 zkEVM written in Rust & SP1.
- [SP1 Tendermint](https://github.com/succinctlabs/sp1-tendermint-example): An example of a ZK Tendermint light client on Ethereum powered by SP1.
- and many more!

