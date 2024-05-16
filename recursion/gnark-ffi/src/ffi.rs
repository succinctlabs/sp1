use crate::Groth16Proof;
use std::{
    ffi::{c_char, CString},
    sync::Mutex,
};

mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bind::*;

pub fn prove_groth16(data_dir: &str, witness_path: &str) -> Groth16Proof {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    let witness_path = CString::new(witness_path).expect("CString::new failed");

    let proof = unsafe {
        let proof = bind::ProveGroth16(
            data_dir.as_ptr() as *mut c_char,
            witness_path.as_ptr() as *mut c_char,
        ) as *mut C_Groth16Proof;
        // Safety: The pointer is returned from the go code and is guaranteed to be valid.
        unsafe { *proof }
    };

    let result = proof.into_rust();
    println!("result: {:?}", result);
    result
}

pub fn build_groth16(data_dir: &str) {
    let data_dir = CString::new(data_dir).expect("CString::new failed");

    unsafe {
        bind::BuildGroth16(data_dir.as_ptr() as *mut c_char);
    }
}

pub fn verify_groth16(
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
        bind::VerifyGroth16(
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

pub fn test_groth16(witness_json: &str, constraints_json: &str) {
    test_init();
    let witness_json = CString::new(witness_json).expect("CString::new failed");
    let build_dir = CString::new(constraints_json).expect("CString::new failed");
    unsafe {
        bind::TestGroth16(
            witness_json.as_ptr() as *mut c_char,
            build_dir.as_ptr() as *mut c_char,
        );
    }
}

// Global test init semaphore to ensure that the test is only initialized once, but must be finished
// at least once
static mut TEST_INIT_LOCK: Mutex<bool> = Mutex::new(false);

fn test_init() {
    unsafe {
        let mut lock = TEST_INIT_LOCK.lock().unwrap();
        if !*lock {
            bind::TestInit();
            *lock = true;
        }
    }
}

/// Converts a C string into a Rust String.
///
/// # Safety
/// This function consumes the input pointer, so the caller must ensure that the pointer is not used
/// after this function is called.
unsafe fn c_char_ptr_to_string(input: *mut c_char) -> String {
    unsafe {
        CString::from_raw(input) // Converts a pointer that C uses into a CString
            .into_string()
            .expect("CString::into_string failed")
    }
}

impl C_Groth16Proof {
    fn into_rust(self) -> Groth16Proof {
        // Safety: The raw pointers are not used anymore after converted into Rust strings.
        unsafe {
            Groth16Proof {
                public_inputs: [
                    c_char_ptr_to_string(self.PublicInputs[0]),
                    c_char_ptr_to_string(self.PublicInputs[1]),
                ],
                encoded_proof: c_char_ptr_to_string(self.EncodedProof),
                raw_proof: c_char_ptr_to_string(self.RawProof),
            }
        }
    }
}
