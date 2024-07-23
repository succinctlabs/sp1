# Contract Addresses

When using SP1, we recommend using our deployed verifiers. Each contract is a [SP1VerifierGateway](https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/src/ISP1VerifierGateway.sol) which can automatically routes your SP1 proof to the correct verifier based on the prover version.

| Chain ID | Chain            | Gateway                                                                                                                         |
| -------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Mainnet          | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)           |
| 11155111 | Sepolia          | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)   |
| 17000    | Holesky          | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://holesky.etherscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)   |
| 42161    | Arbitrum One     | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://arbiscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)            |
| 421614   | Arbitrum Sepolia | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.arbiscan.io/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)    |
| 534351   | Scroll Sepolia   | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.scrollscan.com/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e) |
| 534352   | Scroll           | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://scrollscan.com/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)         |
| 8453     | Base             | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://basescan.org/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)           |
| 84532    | Base Sepolia     | [0x3B6041173B80E77f038f3F2C0f9744f04837185e](https://sepolia.basescan.org/address/0x3B6041173B80E77f038f3F2C0f9744f04837185e)   |

**Currently officially supported version of SP1 is v1.0.1.** If you'd like official support for a verifier on a different chain, please ask in the [SP1 Telegram](https://t.me/succinct_sp1).

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
