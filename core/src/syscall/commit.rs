use crate::runtime::{Syscall, SyscallContext};

pub struct SyscallCommit;

impl SyscallCommit {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallCommit {
    fn execute(
        &self,
        _ctx: &mut SyscallContext,
        _pi_digest_word: u32,
        _word_idx: u32,
    ) -> Option<u32> {
        // Do a no-op.  This ecall is used to verify that a word within the public input digest is
        // correct.

        None
    }
}
