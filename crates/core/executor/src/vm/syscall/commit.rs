use crate::{vm::syscall::SyscallRuntime, ExecutionMode, SyscallCode};

pub(crate) fn commit_syscall<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    _: SyscallCode,
    word_idx: u64,
    public_values_digest_word: u64,
) -> Option<u64> {
    let digest_word: u32 =
        public_values_digest_word.try_into().expect("digest word should fit in u32");
    rt.core_mut().public_value_digest[word_idx as usize] = digest_word;
    if RT::TRACING {
        let record = rt.record_mut();

        record.public_values.committed_value_digest[word_idx as usize] = digest_word;

        record.public_values.commit_syscall = 1;
    }

    None
}
