#![no_main]
sp1_zkvm::entrypoint!(main);

/// To add testing for a new patch, add a new case to the function below.
pub fn main() {
    #[cfg(target_os = "zkvm")]
    {
        use patch_testing_program::tests::*;
        use patch_testing_program::TestName;

        let test_name = sp1_zkvm::io::read::<TestName>();

        match test_name {
            TestName::Keccak => test_keccak(),
            TestName::Sha256 => test_sha256(),
            TestName::Curve25519DalekNg => test_curve25519_dalek_ng(),
            TestName::Curve25519Dalek => test_curve25519_dalek(),
            TestName::Ed25519Dalek => test_ed25519_dalek(),
            TestName::Ed25519Consensus => test_ed25519_consensus(),
            TestName::K256 => test_k256_patch(),
            TestName::P256 => test_p256_patch(),
            TestName::Secp256k1 => test_secp256k1_patch(),
        }
    }
}
