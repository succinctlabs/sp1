use super::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct CommitSyscall;

impl Syscall for CommitSyscall {
    #[allow(clippy::mut_mut)]
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        word_idx: u32,
        public_values_digest_word: u32,
    ) -> Option<u32> {
        let rt = &mut ctx.rt;

        rt.record.public_values.committed_value_digest[word_idx as usize] =
            public_values_digest_word;

        None
    }
}
