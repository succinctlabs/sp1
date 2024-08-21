#![no_main]

use kzg_rs::{Blob, Bytes32, Bytes48, KzgError, KzgProof, KzgSettings};
use serde::Deserialize;

sp1_zkvm::entrypoint!(main);

#[derive(Debug, Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    z: &'a str,
    y: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.commitment)
    }

    pub fn get_z(&self) -> Result<Bytes32, KzgError> {
        Bytes32::from_hex(self.z)
    }

    pub fn get_y(&self) -> Result<Bytes32, KzgError> {
        Bytes32::from_hex(self.y)
    }

    pub fn get_proof(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.proof)
    }
}

#[derive(Debug, Deserialize)]
pub struct Test<I> {
    pub input: I,
    output: Option<bool>,
}

impl<I> Test<I> {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}

#[derive(Debug, Deserialize)]
pub struct BlobInput<'a> {
    blob: &'a str,
    commitment: &'a str,
    proof: &'a str,
}

impl BlobInput<'_> {
    pub fn get_blob(&self) -> Result<Blob, KzgError> {
        Blob::from_hex(self.blob)
    }

    pub fn get_commitment(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.commitment)
    }

    pub fn get_proof(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.proof)
    }
}

#[derive(Debug, Deserialize)]
struct BlobBatchInput<'a> {
    #[serde(borrow)]
    blob: &'a str,
    #[serde(borrow)]
    commitment: &'a str,
    #[serde(borrow)]
    proof: &'a str,
}

impl<'a> BlobBatchInput<'a> {
    pub fn get_blobs(&self) -> Result<Blob, KzgError> {
        Blob::from_hex(self.blob)
    }

    pub fn get_commitments(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.commitment)
    }

    pub fn get_proofs(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.proof)
    }
}

pub fn main() {
    let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
    {
        const VERIFY_KZG_PROOF_TEST: &str = include_str!("../../tests/verify_kzg_proof_test.yaml");
        let test: Test<Input> =
            serde_yaml::from_str(VERIFY_KZG_PROOF_TEST).expect("failed to parse test");
        let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
            test.input.get_commitment(),
            test.input.get_z(),
            test.input.get_y(),
            test.input.get_proof(),
        ) else {
            assert!(test.get_output().is_none());
            return;
        };
        println!("cycle-tracker-start: verify-kzg-proof");
        let _ = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings);
        println!("cycle-tracker-end: verify-kzg-proof");
    }

    {
        const VERIFY_BLOB_KZG_PROOF_TEST: &str =
            include_str!("../../tests/verify_blob_kzg_proof_test.yaml");
        let test: Test<BlobInput> =
            serde_yaml::from_str(VERIFY_BLOB_KZG_PROOF_TEST).expect("failed to parse test");
        let (Ok(blob), Ok(commitment), Ok(proof)) =
            (test.input.get_blob(), test.input.get_commitment(), test.input.get_proof())
        else {
            assert!(test.get_output().is_none());
            return;
        };

        println!("cycle-tracker-start: verify-blob-kzg-proof");
        let _ = KzgProof::verify_blob_kzg_proof(blob, &commitment, &proof, &kzg_settings);
        println!("cycle-tracker-end: verify-blob-kzg-proof");
    }

    {
        const VERIFY_BLOB_KZG_PROOF_BATCH_TEST: &str =
            include_str!("../../tests/verify_blob_kzg_proof_batch_test.yaml");
        let test: Test<BlobBatchInput> =
            serde_yaml::from_str(VERIFY_BLOB_KZG_PROOF_BATCH_TEST).expect("failed to parse test");
        let (Ok(blobs), Ok(commitments), Ok(proofs)) =
            (test.input.get_blobs(), test.input.get_commitments(), test.input.get_proofs())
        else {
            assert!(test.get_output().is_none());
            return;
        };

        println!("cycle-tracker-start: verify-blob-kzg-proof-batch");
        let _ = KzgProof::verify_blob_kzg_proof_batch(
            vec![blobs],
            vec![commitments],
            vec![proofs],
            &kzg_settings,
        );
        println!("cycle-tracker-end: verify-blob-kzg-proof-batch");
    }
}
