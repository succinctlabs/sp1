# Contract Addresses

To verify SP1 proofs on-chain, we recommend using our deployed canonical verifier gateways. The
[SP1VerifierGateway](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol)
will automatically route your SP1 proof to the correct verifier based on the SP1 version used.

## Canonical Verifier Gateways

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
| 11155420 | Optimism Sepolia | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia-optimism.etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e) |
| 534351   | Scroll Sepolia   | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.scrollscan.com/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)         |
| 534352   | Scroll           | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://scrollscan.com/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)                 |

The most up-to-date reference on each chain can be found in the
[deployments](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/deployments)
directory in the
SP1 contracts repository, where each chain has a dedicated JSON file with each verifier's address.

## Versioning Policy

Whenever a verifier for a new SP1 version is deployed, the gateway contract will be updated to
support it with
[addRoute()](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol#L65).
If a verifier for an SP1 version has an issue, the route will be frozen with
[freezeRoute()](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol#L71).

On mainnets, only official versioned releases are deployed and added to the gateway. Testnets have
`rc` versions of the verifier deployed supported in addition to the official versions.

## Deploying to other Chains

In the case that you need to use a chain that is not listed above, you can deploy your own
verifier contract by following the instructions in the
[SP1 Contracts Repo](https://github.com/succinctlabs/sp1-contracts/blob/main/README.md#deployments).

Since both the `SP1VerifierGateway` and each `SP1Verifier` implement the [ISP1Verifier
interface](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1Verifier.sol), you can choose to either:

* Deploy the `SP1VerifierGateway` and add `SP1Verifier` contracts to it. Then point to the
  `SP1VerifierGateway` address in your contracts.
* Deploy just the `SP1Verifier` contract that you want to use. Then point to the `SP1Verifier`
  address in
  your contracts.

If you want support for a canonical verifier on your chain, contact us [here](https://t.me/+AzG4ws-kD24yMGYx). We often deploy canonical verifiers on new chains if there's enough demand.

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
