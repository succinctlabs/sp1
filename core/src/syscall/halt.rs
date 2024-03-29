use crate::runtime::{Syscall, SyscallContext};
use sha2::Digest;
use sp1_zkvm::PI_DIGEST_WORD_SIZE;

pub struct SyscallHalt;

impl SyscallHalt {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext, exit_code: u32, _: u32) -> Option<u32> {
        let rt = &mut ctx.rt;

        let pi_digest = rt
            .pi_hasher
            .take()
            .expect("runtime pi hasher should be Some")
            .finalize();
        let mut pi_digest_words = [0u32; PI_DIGEST_WORD_SIZE];
        for i in 0..PI_DIGEST_WORD_SIZE {
            pi_digest_words[i] =
                u32::from_le_bytes(pi_digest.as_slice()[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        rt.pi_digest = Some(pi_digest_words);

        if rt.fail_on_panic && exit_code != 0 {
            panic!(
                "RISC-V runtime halted during program execution with non-zero exit code {}. This likely means your program panicked during execution.",
                exit_code
            );
        }

        ctx.set_next_pc(0);
        None
    }
}
