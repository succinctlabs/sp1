use crate::runtime::{Syscall, SyscallContext};

/// A syscall that commits a word of the public values digest.
pub struct SyscallCommit;

impl SyscallCommit {
    pub const fn new() -> Self {
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
            public_values_digest_word;

        None
    }
}

/// Commit to one word within the digest of deferred proofs. Takes in an index and a word.
pub struct SyscallCommitDeferred;

impl SyscallCommitDeferred {
    pub const fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallCommitDeferred {
    fn execute(&self, ctx: &mut SyscallContext, word_idx: u32, word: u32) -> Option<u32> {
        let rt = &mut ctx.rt;

        rt.record.public_values.deferred_proofs_digest[word_idx as usize] = word;

        None
    }
}
