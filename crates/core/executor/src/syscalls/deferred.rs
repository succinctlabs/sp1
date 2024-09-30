use super::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct CommitDeferredSyscall;

impl Syscall for CommitDeferredSyscall {
    #[allow(clippy::mut_mut)]
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        word_idx: u32,
        word: u32,
    ) -> Option<u32> {
        let rt = &mut ctx.rt;

        rt.record.public_values.deferred_proofs_digest[word_idx as usize] = word;

        None
    }
}
