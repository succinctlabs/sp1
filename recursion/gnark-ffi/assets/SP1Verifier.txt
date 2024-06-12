// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISP1Verifier} from "./ISP1Verifier.sol";
import {PlonkVerifier} from "./PlonkVerifier.sol";

/// @title SP1 Verifier
/// @author Succinct Labs
/// @notice This contracts implements a solidity verifier for SP1.
contract SP1Verifier is PlonkVerifier {
    function VERSION() external pure returns (string memory) {
        return "TODO";
    }

    /// @notice Hashes the public values to a field elements inside Bn254.
    /// @param publicValues The public values.
    function hashPublicValues(
        bytes memory publicValues
    ) public pure returns (bytes32) {
        return sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    }

    /// @notice Verifies a proof with given public values and vkey.
    /// @param vkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(
        bytes32 vkey,
        bytes memory publicValues,
        bytes memory proofBytes
    ) public view {
        bytes32 publicValuesDigest = hashPublicValues(publicValues);
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(vkey);
        inputs[1] = uint256(publicValuesDigest);
        this.Verify(proofBytes, inputs);
    }
}