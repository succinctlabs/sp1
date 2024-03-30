use crate::{
    air::PiDigest,
    runtime::{Syscall, SyscallContext},
};
use sha2::{Digest, Sha256};

pub struct SyscallHalt;

impl SyscallHalt {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext, exit_code: u32, _: u32) -> Option<u32> {
        let rt = &mut ctx.rt;

        let mut pi_hasher = Sha256::new();
        pi_hasher.update(&rt.pi_buffer);
        let pi_digest_bytes: &[u8] = &pi_hasher.finalize();

        let pi_digest: PiDigest<u32> = pi_digest_bytes.into();
        rt.pi_digest = Some(pi_digest);

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
