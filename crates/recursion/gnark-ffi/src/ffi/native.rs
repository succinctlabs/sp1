#![allow(unused)]

//! FFI bindings for the Go code. The functions exported in this module are safe to call from Rust.
//! All C strings and other C memory should be freed in Rust, including C Strings returned by Go.
//! Although we cast to *mut c_char because the Go signatures can't be immutable, the Go functions
//! should not modify the strings.

use crate::{Groth16Bn254Proof, PlonkBn254Proof, SP1_CIRCUIT_VERSION};
use cfg_if::cfg_if;
use std::{
    ffi::{c_char, CStr, CString},
    mem::forget,
};

#[allow(warnings, clippy::all)]
mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bind::*;

enum ProofSystem {
    Plonk,
    Groth16,
}

enum ProofResult {
    Plonk(*mut C_PlonkBn254Proof),
    Groth16(*mut C_Groth16Bn254Proof),
}

impl ProofSystem {
    fn build_fn(&self) -> unsafe extern "C" fn(*mut c_char) {
        match self {
            ProofSystem::Plonk => bind::BuildPlonkBn254,
            ProofSystem::Groth16 => bind::BuildGroth16Bn254,
        }
    }

    fn prove_fn(&self) -> ProveFunction {
        match self {
            ProofSystem::Plonk => ProveFunction::Plonk(bind::ProvePlonkBn254),
            ProofSystem::Groth16 => ProveFunction::Groth16(bind::ProveGroth16Bn254),
        }
    }

    fn verify_fn(
        &self,
    ) -> unsafe extern "C" fn(
        *mut c_char,
        *mut c_char,
        *mut c_char,
        *mut c_char,
        *mut c_char,
        *mut c_char,
        *mut c_char,
    ) -> *mut c_char {
        match self {
            ProofSystem::Plonk => bind::VerifyPlonkBn254,
            ProofSystem::Groth16 => bind::VerifyGroth16Bn254,
        }
    }

    fn test_fn(&self) -> unsafe extern "C" fn(*mut c_char, *mut c_char) -> *mut c_char {
        match self {
            ProofSystem::Plonk => bind::TestPlonkBn254,
            ProofSystem::Groth16 => bind::TestGroth16Bn254,
        }
    }
}

enum ProveFunction {
    Plonk(unsafe extern "C" fn(*mut c_char, *mut c_char) -> *mut C_PlonkBn254Proof),
    Groth16(unsafe extern "C" fn(*mut c_char, *mut c_char) -> *mut C_Groth16Bn254Proof),
}

fn build(system: ProofSystem, data_dir: &str) {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    unsafe {
        (system.build_fn())(data_dir.as_ptr() as *mut c_char);
    }
}

fn prove(system: ProofSystem, data_dir: &str, witness_path: &str) -> ProofResult {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    let witness_path = CString::new(witness_path).expect("CString::new failed");

    unsafe {
        match system.prove_fn() {
            ProveFunction::Plonk(func) => {
                let proof =
                    func(data_dir.as_ptr() as *mut c_char, witness_path.as_ptr() as *mut c_char);
                ProofResult::Plonk(proof)
            }
            ProveFunction::Groth16(func) => {
                let proof =
                    func(data_dir.as_ptr() as *mut c_char, witness_path.as_ptr() as *mut c_char);
                ProofResult::Groth16(proof)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify(
    system: ProofSystem,
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
    exit_code: &str,
    vk_root: &str,
    proof_nonce: &str,
) -> Result<(), String> {
    let data_dir = CString::new(data_dir).expect("CString::new failed");
    let proof = CString::new(proof).expect("CString::new failed");
    let vkey_hash = CString::new(vkey_hash).expect("CString::new failed");
    let committed_values_digest =
        CString::new(committed_values_digest).expect("CString::new failed");
    let exit_code = CString::new(exit_code).expect("CString::new failed");
    let proof_nonce = CString::new(proof_nonce).expect("CString::new failed");
    let vk_root = CString::new(vk_root).expect("CString::new failed");

    let err_ptr = unsafe {
        (system.verify_fn())(
            data_dir.as_ptr() as *mut c_char,
            proof.as_ptr() as *mut c_char,
            vkey_hash.as_ptr() as *mut c_char,
            committed_values_digest.as_ptr() as *mut c_char,
            exit_code.as_ptr() as *mut c_char,
            vk_root.as_ptr() as *mut c_char,
            proof_nonce.as_ptr() as *mut c_char,
        )
    };
    if err_ptr.is_null() {
        Ok(())
    } else {
        unsafe {
            // Safety: The error message is returned from the go code and is guaranteed to be valid.
            Err(ptr_to_string_freed(err_ptr))
        }
    }
}

fn test(system: ProofSystem, witness_json: &str, constraints_json: &str) {
    unsafe {
        let witness_json = CString::new(witness_json).expect("CString::new failed");
        let constraints_json = CString::new(constraints_json).expect("CString::new failed");
        let err_ptr = (system.test_fn())(
            witness_json.as_ptr() as *mut c_char,
            constraints_json.as_ptr() as *mut c_char,
        );
        if !err_ptr.is_null() {
            // Safety: The error message is returned from the go code and is guaranteed to be valid.
            panic!("Test failed: {:?}", ptr_to_string_freed(err_ptr));
        }
    }
}

// Public API functions

pub fn build_plonk_bn254(data_dir: &str) {
    build(ProofSystem::Plonk, data_dir)
}

pub fn prove_plonk_bn254(data_dir: &str, witness_path: &str) -> PlonkBn254Proof {
    match prove(ProofSystem::Plonk, data_dir, witness_path) {
        ProofResult::Plonk(proof) => unsafe { plonk_bn254_proof_from_raw(proof) },
        _ => unreachable!(),
    }
}

/// Low-level native FFI entry point; does not enforce SP1's exit-code policy.
/// For SP1 proofs, use [`crate::PlonkBn254Prover::verify`] to enforce the
/// zero-exit-code policy when `experimental` is disabled.
pub fn verify_plonk_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
    exit_code: &str,
    vk_root: &str,
    proof_nonce: &str,
) -> Result<(), String> {
    verify(
        ProofSystem::Plonk,
        data_dir,
        proof,
        vkey_hash,
        committed_values_digest,
        exit_code,
        vk_root,
        proof_nonce,
    )
}

pub fn test_plonk_bn254(witness_json: &str, constraints_json: &str) {
    test(ProofSystem::Plonk, witness_json, constraints_json)
}

pub fn build_groth16_bn254(data_dir: &str) {
    build(ProofSystem::Groth16, data_dir)
}

pub fn prove_groth16_bn254(data_dir: &str, witness_path: &str) -> Groth16Bn254Proof {
    match prove(ProofSystem::Groth16, data_dir, witness_path) {
        ProofResult::Groth16(proof) => unsafe { groth16_bn254_proof_from_raw(proof) },
        _ => unreachable!(),
    }
}

/// Low-level native FFI entry point; does not enforce SP1's exit-code policy.
/// For SP1 proofs, use [`crate::Groth16Bn254Prover::verify`] to enforce the
/// zero-exit-code policy when `experimental` is disabled.
pub fn verify_groth16_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
    exit_code: &str,
    vk_root: &str,
    proof_nonce: &str,
) -> Result<(), String> {
    verify(
        ProofSystem::Groth16,
        data_dir,
        proof,
        vkey_hash,
        committed_values_digest,
        exit_code,
        vk_root,
        proof_nonce,
    )
}

pub fn test_groth16_bn254(witness_json: &str, constraints_json: &str) {
    test(ProofSystem::Groth16, witness_json, constraints_json)
}

pub fn test_koalabear_poseidon2() {
    unsafe {
        let err_ptr = bind::TestPoseidonKoalaBear2();
        if !err_ptr.is_null() {
            // Safety: The error message is returned from the go code and is guaranteed to be valid.
            panic!("TestPoseidonKoalaBear2 failed: {}", ptr_to_string_freed(err_ptr));
        }
    }
}

/// Converts a C string into a Rust String.
///
/// # Safety
/// This function does not free the pointer, so the caller must ensure that the pointer is handled
/// correctly.
unsafe fn ptr_to_string_cloned(input: *mut c_char) -> String {
    CStr::from_ptr(input).to_owned().into_string().expect("CStr::into_string failed")
}

/// Converts a C string into a Rust String.
///
/// # Safety
/// This function frees the pointer, so the caller must ensure that the pointer is not used
/// after this function is called.
unsafe fn ptr_to_string_freed(input: *mut c_char) -> String {
    let string = ptr_to_string_cloned(input);
    bind::FreeString(input);
    string
}

unsafe fn plonk_bn254_proof_from_raw(c_proof: *mut C_PlonkBn254Proof) -> PlonkBn254Proof {
    let proof = PlonkBn254Proof {
        public_inputs: [
            ptr_to_string_cloned((*c_proof).PublicInputs[0]),
            ptr_to_string_cloned((*c_proof).PublicInputs[1]),
            ptr_to_string_cloned((*c_proof).PublicInputs[2]),
            ptr_to_string_cloned((*c_proof).PublicInputs[3]),
            ptr_to_string_cloned((*c_proof).PublicInputs[4]),
        ],
        encoded_proof: ptr_to_string_cloned((*c_proof).EncodedProof),
        raw_proof: ptr_to_string_cloned((*c_proof).RawProof),
        plonk_vkey_hash: [0; 32],
    };
    bind::FreePlonkBn254Proof(c_proof);
    proof
}

unsafe fn groth16_bn254_proof_from_raw(c_proof: *mut C_Groth16Bn254Proof) -> Groth16Bn254Proof {
    let proof = Groth16Bn254Proof {
        public_inputs: [
            ptr_to_string_cloned((*c_proof).PublicInputs[0]),
            ptr_to_string_cloned((*c_proof).PublicInputs[1]),
            ptr_to_string_cloned((*c_proof).PublicInputs[2]),
            ptr_to_string_cloned((*c_proof).PublicInputs[3]),
            ptr_to_string_cloned((*c_proof).PublicInputs[4]),
        ],
        encoded_proof: ptr_to_string_cloned((*c_proof).EncodedProof),
        raw_proof: ptr_to_string_cloned((*c_proof).RawProof),
        groth16_vkey_hash: [0; 32],
    };
    bind::FreeGroth16Bn254Proof(c_proof);
    proof
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use slop_algebra::AbstractField;
    use slop_symmetric::Permutation;
    use sp1_hypercube::inner_perm;
    use sp1_primitives::SP1Field;

    #[test]
    #[allow(clippy::uninlined_format_args)]
    pub fn test_koalabear_poseidon2() {
        let perm = inner_perm();
        let zeros = [SP1Field::zero(); 16];
        let result = perm.permute(zeros);
        println!("{result:?}");
        super::test_koalabear_poseidon2();
    }
}
