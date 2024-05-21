// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {ISP1Verifier} from "./ISP1Verifier.sol";

/// @title SP1 Mock Verifier
/// @author Succinct Labs
/// @notice This contracts implements a Mock solidity verifier for SP1.
contract SP1MockVerifier is ISP1Verifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @param vkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(
        bytes32 vkey,
        bytes memory publicValues,
        bytes memory proofBytes
    ) external view {
        assert(proofBytes.length == 0);
    }
}
