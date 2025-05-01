# SP1 Dice Game

A provably fair dice rolling game built with [SP1](https://github.com/succinctlabs/sp1). This project demonstrates how to create a zero-knowledge proof for a simple dice game that can be verified on-chain.

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

## Running the Project

There are 3 main ways to run this project: execute the dice game, generate a core proof, and
generate an EVM-compatible proof.

### Build the Program

The program is automatically built through `script/build.rs` when the script is built.

### Execute the Dice Game

To run the dice game without generating a proof:

```sh
cd script
cargo run --release -- --execute --seed 12345
```

This will execute the program with the provided seed and display the dice roll output (a number from 1 to 6).

### Generate an SP1 Core Proof

To generate an SP1 [core proof](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types#core-default) proving your dice roll was fairly generated:

```sh
cd script
cargo run --release -- --prove --seed 12345
```

### Generate an EVM-Compatible Proof

> [!WARNING]
> You will need at least 16GB RAM to generate a Groth16 or PLONK proof. View the [SP1 docs](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements#local-proving) for more information.

Generating a proof that is cheap to verify on the EVM (e.g. Groth16 or PLONK) is more intensive than generating a core proof.

To generate a Groth16 proof:

```sh
cd script
cargo run --release --bin evm -- --system groth16 --seed 12345
```

To generate a PLONK proof:

```sh
cd script
cargo run --release --bin evm -- --system plonk --seed 12345
```

These commands will also generate fixtures that can be used to test the verification of SP1 proofs
inside Solidity.

### Retrieve the Verification Key

To retrieve your `programVKey` for your on-chain contract, run the following command in `script`:

```sh
cargo run --release --bin vkey
```

## Using the Prover Network

We highly recommend using the [Succinct Prover Network](https://docs.succinct.xyz/docs/network/introduction) for any non-trivial programs or benchmarking purposes. For more information, see the [key setup guide](https://docs.succinct.xyz/docs/network/developers/key-setup) to get started.

To get started, copy the example environment file:

```sh
cp .env.example .env
```

Then, set the `SP1_PROVER` environment variable to `network` and set the `NETWORK_PRIVATE_KEY`
environment variable to your whitelisted private key.

For example, to generate an EVM-compatible proof using the prover network, run the following
command:

```sh
SP1_PROVER=network NETWORK_PRIVATE_KEY=... cargo run --release --bin evm --seed 12345
```

## How It Works

1. A user provides a seed value
2. The program computes a deterministic dice roll value (1-6) based on that seed
3. A zero-knowledge proof is generated, proving that the dice roll was correctly computed
4. The proof can be verified by anyone, ensuring the fairness of the dice roll

## Project Structure

- `lib/`: Contains the core dice rolling functions and data structures
- `program/`: Contains the RISC-V program that will be executed in the zkVM
- `script/`: Contains scripts for executing and proving program execution