use crate::{
    runtime::{Syscall, SyscallContext},
    stark::MachineRecord,
};

pub struct SyscallCommit;

impl SyscallCommit {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallCommit {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        word_idx: u32,
        public_values_digest_word: u32,
    ) -> Option<u32> {
        let rt = &mut ctx.rt;

        let public_values_digest = rt.record.public_values_digest_mut();
        public_values_digest[word_idx as usize] = public_values_digest_word;

        None
    }
}
