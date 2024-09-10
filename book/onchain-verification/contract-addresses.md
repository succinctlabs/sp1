# Contract Addresses

To verify SP1 proofs on-chain, we recommend using our deployed verifier gateways. For the chains listed below, an [SP1VerifierGateway](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol) can automatically route your SP1 proof to the correct verifier based on the SP1 version.

| Chain ID | Chain            | Gateway                                                                                                                                 |
| -------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Mainnet          | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)                   |
| 11155111 | Sepolia          | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)           |
| 17000    | Holesky          | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://holesky.etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)           |
| 42161    | Arbitrum One     | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://arbiscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)                    |
| 421614   | Arbitrum Sepolia | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.arbiscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)            |
| 8453     | Base             | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://basescan.org/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)                   |
| 84532    | Base Sepolia     | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.basescan.org/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)           |
| 10       | Optimism         | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://optimistic.etherscan.io/address/0x3b6041173b80e77f038f3f2c0f9744f04837185e)        |
| 11155420 | Optimism Sepolia | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](hhttps://sepolia-optimism.etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e) |
| 534351   | Scroll Sepolia   | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.scrollscan.com/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)         |
| 534352   | Scroll           | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://scrollscan.com/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)                 |

A complete reference for all of the SP1Verifier contract addresses can be also be found in the [SP1 Contracts Repo](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/deployments).

Whenever a verifier for a new SP1 version is deployed, the gateway contract will be updated to support it with [addRoute()](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol#L65). If a verifier for an SP1 version has an issue, the route will be frozen with [freezeRoute()](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol#L71).

## ISP1Verifier Interface

All verifiers implement the [ISP1Verifier](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1Verifier.sol) interface.

```c++
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SP1 Verifier Interface
/// @author Succinct Labs
/// @notice This contract is the interface for the SP1 Verifier.
interface ISP1Verifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @dev It is expected that the first 4 bytes of proofBytes must match the first 4 bytes of
    /// target verifier's VERIFIER_HASH.
    /// @param programVKey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
```
