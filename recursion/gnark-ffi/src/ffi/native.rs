#![allow(unused)]

//! FFI bindings for the Go code. The functions exported in this module are safe to call from Rust.
//! All C strings and other C memory should be freed in Rust, including C Strings returned by Go.
//! Although we cast to *mut c_char because the Go signatures can't be immutable, the Go functions
//! should not modify the strings.

use crate::PlonkBn254Proof;
use cfg_if::cfg_if;
use sp1_core::SP1_CIRCUIT_VERSION;
use std::ffi::{c_char, CString};

#[allow(warnings, clippy::all)]
mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bind::*;

pub fn prove_plonk_bn254(data_dir: &str, witness_path: &str) -> PlonkBn254Proof {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    let witness_path = CString::new(witness_path).expect("CString::new failed");

    let proof = unsafe {
        let proof = bind::ProvePlonkBn254(
            data_dir.as_ptr() as *mut c_char,
            witness_path.as_ptr() as *mut c_char,
        );
        // Safety: The pointer is returned from the go code and is guaranteed to be valid.
        *proof
    };

    proof.into_rust()
}

pub fn build_plonk_bn254(data_dir: &str) {
    let data_dir = CString::new(data_dir).expect("CString::new failed");

    unsafe {
        bind::BuildPlonkBn254(data_dir.as_ptr() as *mut c_char);
    }
}

pub fn verify_plonk_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
) -> Result<(), String> {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    let proof = CString::new(proof).expect("CString::new failed");
    let vkey_hash = CString::new(vkey_hash).expect("CString::new failed");
    let committed_values_digest =
        CString::new(committed_values_digest).expect("CString::new failed");

    let err_ptr = unsafe {
        bind::VerifyPlonkBn254(
            data_dir.as_ptr() as *mut c_char,
            proof.as_ptr() as *mut c_char,
            vkey_hash.as_ptr() as *mut c_char,
            committed_values_digest.as_ptr() as *mut c_char,
        )
    };
    if err_ptr.is_null() {
        Ok(())
    } else {
        // Safety: The error message is returned from the go code and is guaranteed to be valid.
        let err = unsafe { CString::from_raw(err_ptr) };
        Err(err.into_string().unwrap())
    }
}

pub fn test_plonk_bn254(witness_json: &str, constraints_json: &str) {
    unsafe {
        let witness_json = CString::new(witness_json).expect("CString::new failed");
        let build_dir = CString::new(constraints_json).expect("CString::new failed");
        let err_ptr = bind::TestPlonkBn254(
            witness_json.as_ptr() as *mut c_char,
            build_dir.as_ptr() as *mut c_char,
        );
        if !err_ptr.is_null() {
            // Safety: The error message is returned from the go code and is guaranteed to be valid.
            let err = CString::from_raw(err_ptr);
            panic!("TestPlonkBn254 failed: {}", err.into_string().unwrap());
        }
    }
}

pub fn test_babybear_poseidon2() {
    unsafe {
        let err_ptr = bind::TestPoseidonBabyBear2();
        if !err_ptr.is_null() {
            // Safety: The error message is returned from the go code and is guaranteed to be valid.
            let err = CString::from_raw(err_ptr);
            panic!("TestPlonkBn254 failed: {}", err.into_string().unwrap());
        }
    }
}

/// Converts a C string into a Rust String.
///
/// # Safety
/// This function frees the string memory, so the caller must ensure that the pointer is not used
/// after this function is called.
unsafe fn c_char_ptr_to_string(input: *mut c_char) -> String {
    unsafe {
        CString::from_raw(input) // Converts a pointer that C uses into a CString
            .into_string()
            .expect("CString::into_string failed")
    }
}

impl C_PlonkBn254Proof {
    /// Converts a C PlonkBn254Proof into a Rust PlonkBn254Proof, freeing the C strings.
    fn into_rust(self) -> PlonkBn254Proof {
        // Safety: The raw pointers are not used anymore after converted into Rust strings.
        unsafe {
            PlonkBn254Proof {
                public_inputs: [
                    c_char_ptr_to_string(self.PublicInputs[0]),
                    c_char_ptr_to_string(self.PublicInputs[1]),
                ],
                encoded_proof: c_char_ptr_to_string(self.EncodedProof),
                raw_proof: c_char_ptr_to_string(self.RawProof),
                plonk_vkey_hash: [0; 32],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_symmetric::Permutation;

    #[test]
    pub fn test_babybear_poseidon2() {
        let perm = sp1_core::utils::inner_perm();
        let zeros = [BabyBear::zero(); 16];
        let result = perm.permute(zeros);
        println!("{:?}", result);
        super::test_babybear_poseidon2();
    }
}
