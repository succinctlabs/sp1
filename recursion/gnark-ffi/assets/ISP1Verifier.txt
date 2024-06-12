// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SP1 Verifier Interface
/// @author Succinct Labs
/// @notice This contract is the interface for the SP1 Verifier.
interface ISP1Verifier {
    /// @notice Returns the version of the SP1 Verifier.
    function VERSION() external pure returns (string memory);

    /// @notice Verifies a proof with given public values and vkey.
    /// @param vkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(
        bytes32 vkey,
        bytes memory publicValues,
        bytes memory proofBytes
    ) external view;
}
