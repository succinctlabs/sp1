use crate::Groth16Proof;
use std::ffi::{c_char, CString};

mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bind::*;

pub fn prove_groth16(data_dir: &str, witness_path: &str) -> Groth16Proof {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    let witness_path = CString::new(witness_path).expect("CString::new failed");

    println!("proving");
    let proof = unsafe {
        let proof = bind::ProveGroth16(
            data_dir.as_ptr() as *mut i8,
            witness_path.as_ptr() as *mut i8,
        ) as *mut C_Groth16Proof;
        println!("proof: {:?}", proof);
        println!("got proof");
        unsafe { *proof }
    };
    println!("done proving");

    let result = proof.into();
    println!("result: {:?}", result);
    result
}

pub fn build_groth16(data_dir: &str) {
    let data_dir = CString::new(data_dir).expect("CString::new failed");

    unsafe {
        bind::BuildGroth16(data_dir.as_ptr() as *mut i8);
    }
}

fn string_to_c_char_ptr(input: String) -> *mut c_char {
    let c_string = CString::new(input).expect("CString::new failed");
    c_string.into_raw() // Converts CString into a pointer that C can use
}

fn c_char_ptr_to_string(input: *mut c_char) -> String {
    unsafe {
        CString::from_raw(input) // Converts a pointer that C uses into a CString
            .to_str()
            .expect("CString::to_str failed")
            .to_string()
    }
}

impl From<Groth16Proof> for C_Groth16Proof {
    fn from(proof: Groth16Proof) -> Self {
        // Convert Rust String to *c_char
        Self {
            PublicInputs: [
                string_to_c_char_ptr(proof.public_inputs[0].clone()),
                string_to_c_char_ptr(proof.public_inputs[1].clone()),
            ],
            EncodedProof: string_to_c_char_ptr(proof.encoded_proof),
            RawProof: string_to_c_char_ptr(proof.raw_proof),
        }
    }
}

impl C_Groth16Proof {
    pub fn free(self) {
        unsafe {
            // Convert *c_char to CString and free it
            CString::from_raw(self.PublicInputs[0]);
            CString::from_raw(self.PublicInputs[1]);
            CString::from_raw(self.EncodedProof);
            CString::from_raw(self.RawProof);
        }
    }
}

impl From<C_Groth16Proof> for Groth16Proof {
    fn from(proof: C_Groth16Proof) -> Self {
        let res = Self {
            public_inputs: [
                c_char_ptr_to_string(proof.PublicInputs[0]),
                c_char_ptr_to_string(proof.PublicInputs[1]),
            ],
            encoded_proof: c_char_ptr_to_string(proof.EncodedProof),
            raw_proof: c_char_ptr_to_string(proof.RawProof),
        };
        proof.free();
        res
    }
}
