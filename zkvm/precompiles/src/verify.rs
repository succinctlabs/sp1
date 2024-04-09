use crate::syscall_verify_sp1_proof;

pub fn verify_sp1_proof(commitment: &[u32; 8], proof: &[u8]) {
    unsafe {
        syscall_verify_sp1_proof(commitment, proof.as_ptr(), proof.len());
    }
}
