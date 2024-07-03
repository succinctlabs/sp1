# Solidity SDK

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
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the fibonacci program.
    bytes32 public fibonacciProgramVkey;

    constructor(address _verifier, bytes32 _fibonacciProgramVkey) {
        verifier = _verifier;
        fibonacciProgramVkey = _fibonacciProgramVkey;
    }

    /// @notice The entrypoint for verifying the proof of a fibonacci number.
    /// @param proof The encoded proof.
    /// @param publicValues The encoded public values.
    function verifyFibonacciProof(bytes calldata proof, bytes calldata publicValues)
        public
        view
        returns (uint32, uint32, uint32)
    {
        ISP1Verifier(verifier).verifyProof(fibonacciProgramVkey, publicValues, proof);
        (uint32 n, uint32 a, uint32 b) = abi.decode(publicValues, (uint32, uint32, uint32));
        return (n, a, b);
    }
}
```

For more details on the contracts, refer to the [sp1-contracts](https://github.com/succinctlabs/sp1-contracts) repo.

### Testing

To test the contract, we recommend setting up [Foundry Tests](https://book.getfoundry.sh/forge/tests). We have an example of such a test in the [SP1 Project Template](https://github.com/succinctlabs/sp1-project-template/blob/dev/contracts/test/Fibonacci.t.sol).