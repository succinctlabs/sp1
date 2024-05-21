use crate::syscall_verify_sp1_proof;

/// Verifies the next proof in the proof input stream given a pkey digest and public values digest.
///
/// Note: sp1_zkvm must also have feature `verify` enabled for this function to work.
pub fn verify_sp1_proof(pkey_digest: &[u32; 8], pv_digest: &[u8; 32]) {
    unsafe {
        syscall_verify_sp1_proof(pkey_digest, pv_digest);
    }
}
