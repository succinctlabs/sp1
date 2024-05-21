/// @title SP1 Verifier
/// @author Succinct Labs
/// @notice This contracts implements a solidity verifier for SP1.
interface ISP1Verifier {
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
