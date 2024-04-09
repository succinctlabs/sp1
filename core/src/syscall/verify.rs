use crate::runtime::{Syscall, SyscallContext};

/// Verifies an SP1 recursive verifier proof. Note that this syscall only verifies the proof during
/// runtime. The actual constraint-level verification is deferred to the recursive layer, where
/// proofs are witnessed and verified in order to reconstruct the deferred_proofs_digest.
pub struct SyscallVerifySP1Proof;

impl SyscallVerifySP1Proof {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallVerifySP1Proof {
    fn execute(&self, ctx: &mut SyscallContext, ptrs_ptr: u32, proof_len: u32) -> Option<u32> {
        let rt = &mut ctx.rt;

        // ptrs_ptr is a pointer to [u32; 2] which contains the pointers to the vkey and proof.
        assert_eq!(ptrs_ptr % 4, 0, "ptrs_ptr must be word-aligned");
        let vkey_ptr = rt.word(ptrs_ptr);
        let proof_ptr = rt.word(ptrs_ptr + 4);
        assert_eq!(vkey_ptr % 4, 0, "vkey_ptr must be word-aligned");
        assert_eq!(proof_ptr % 4, 0, "proof_ptr must be word-aligned");

        // Read `proof_len` bytes from memory starting at proof_ptr.
        let proof = (0..proof_len)
            .map(|i| rt.byte(proof_ptr + i * 4))
            .collect::<Vec<u8>>();

        // TODO: verify the proof.

        None
    }
}
