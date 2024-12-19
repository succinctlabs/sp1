# Solidity Verifier

We maintain a suite of [contracts](https://github.com/succinctlabs/sp1-contracts/tree/main) used for verifying SP1 proofs onchain. We highly recommend using [Foundry](https://book.getfoundry.sh/).

## Installation

To install the latest release version:

```bash
forge install succinctlabs/sp1-contracts
```

To install a specific version:

```bash
forge install succinctlabs/sp1-contracts@<version>
```

Finally, add `@sp1-contracts/=lib/sp1-contracts/contracts/src/` in `remappings.txt.`

### Usage

Once installed, you can use the contracts in the library by importing them:

```c++
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title Fibonacci.
/// @author Succinct Labs
/// @notice This contract implements a simple example of verifying the proof of a computing a
///         fibonacci number.
contract Fibonacci {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://docs.succinct.xyz/onchain-verification/contract-addresses
    address public verifier;

    /// @notice The verification key for the fibonacci program.
    bytes32 public fibonacciProgramVKey;

    constructor(address _verifier, bytes32 _fibonacciProgramVKey) {
        verifier = _verifier;
        fibonacciProgramVKey = _fibonacciProgramVKey;
    }

    /// @notice The entrypoint for verifying the proof of a fibonacci number.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifyFibonacciProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (uint32, uint32, uint32)
    {
        ISP1Verifier(verifier).verifyProof(fibonacciProgramVKey, _publicValues, _proofBytes);
        (uint32 n, uint32 a, uint32 b) = abi.decode(_publicValues, (uint32, uint32, uint32));
        return (n, a, b);
    }
}

```

### Finding your program vkey

The program vkey (`fibonacciProgramVKey` in the example above) is passed into the `ISP1Verifier` along with the public values and proof bytes. You
can find your program vkey by going through the following steps:

1. Find what version of SP1 crates you are using.
2. Use the version from step to run this command: `sp1up --version <version>`
3. Use the vkey command to get the program vkey: `cargo prove vkey -elf <path/to/elf>`

Alternatively, you can set up a simple script to do this using the `sp1-sdk` crate:

```rust
fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (_, vk) = client.setup(FIBONACCI_ELF);

    // Print the verification key.
    println!("Program Verification Key: {}", vk.bytes32());
}
```

### Testing

To test the contract, we recommend setting up [Foundry
Tests](https://book.getfoundry.sh/forge/tests). We have an example of such a test in the [SP1
Project
Template](https://github.com/succinctlabs/sp1-project-template/blob/dev/contracts/test/Fibonacci.t.sol).

### Solidity Versions

The officially deployed contracts are built using Solidity 0.8.20 and exist on the
[sp1-contracts main](https://github.com/succinctlabs/sp1-contracts/tree/main) branch.

If you need to use different versions that are compatible with your contracts, there are also other
branches you can install that contain different versions. For
example for branch [main-0.8.15](https://github.com/succinctlabs/sp1-contracts/tree/main-0.8.15)
contains the contracts with:

```c++
pragma solidity ^0.8.15;
```

and you can install it with:

```sh
forge install succinctlabs/sp1-contracts@main-0.8.15
```

If there is different versions that you need but there aren't branches for them yet, please ask in
the [SP1 Telegram](https://t.me/+AzG4ws-kD24yMGYx).
