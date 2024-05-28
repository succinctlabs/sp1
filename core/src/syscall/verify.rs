use crate::{
    runtime::{Syscall, SyscallContext},
    stark::{RiscvAir, StarkGenericConfig},
    utils::BabyBearPoseidon2Inner,
};

/// Verifies an SP1 recursive verifier proof. Note that this syscall only verifies the proof during
/// runtime. The actual constraint-level verification is deferred to the recursive layer, where
/// proofs are witnessed and verified in order to reconstruct the deferred_proofs_digest.
pub struct SyscallVerifySP1Proof;

impl SyscallVerifySP1Proof {
    pub const fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallVerifySP1Proof {
    #[allow(unused_variables, unused_mut)]
    fn execute(&self, ctx: &mut SyscallContext, vkey_ptr: u32, pv_digest_ptr: u32) -> Option<u32> {
        let rt = &mut ctx.rt;

        // vkey_ptr is a pointer to [u32; 8] which contains the verification key.
        assert_eq!(vkey_ptr % 4, 0, "vkey_ptr must be word-aligned");
        // pv_digest_ptr is a pointer to [u32; 8] which contains the public values digest.
        assert_eq!(pv_digest_ptr % 4, 0, "pv_digest_ptr must be word-aligned");

        let vkey = (0..8)
            .map(|i| rt.word(vkey_ptr + i * 4))
            .collect::<Vec<u32>>();

        let pv_digest = (0..8)
            .map(|i| rt.word(pv_digest_ptr + i * 4))
            .collect::<Vec<u32>>();

        let (proof, proof_vk) = &rt.state.proof_stream[rt.state.proof_stream_ptr];
        rt.state.proof_stream_ptr += 1;

        let config = BabyBearPoseidon2Inner::new();
        let mut challenger = config.challenger();
        // TODO: need to use RecursionAir here
        let machine = RiscvAir::machine(config);

        // TODO: Need to import PublicValues from recursion.
        // Assert the commit in vkey from runtime inputs matches the one from syscall.
        // Assert that the public values digest from runtime inputs matches the one from syscall.

        // TODO: Verify proof
        // machine
        //     .verify(proof_vk, proof, &mut challenger)
        //     .expect("proof verification failed");

        None
    }
}
