use crate::{
    air::Word,
    runtime::{Syscall, SyscallContext},
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

        rt.record.public_values.committed_value_digest[word_idx as usize] =
            Word::<u32>::from_u32(public_values_digest_word);

        None
    }
}
