/// @title SP1 Verifier
/// @author Succinct Labs
/// @notice This contracts implements a solidity verifier for SP1.
interface ISP1Verifier {
    /// @notice Deserializes a proof from the given bytes.
    /// @param proofBytes The proof bytes.
    function deserializeProof(
        bytes memory proofBytes
    )
        external
        pure
        returns (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok
        );

    /// @notice Hashes the public values to a field elements inside Bn254.
    /// @param publicValues The public values.
    function hashPublicValues(
        bytes memory publicValues
    ) external pure returns (bytes32);

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
