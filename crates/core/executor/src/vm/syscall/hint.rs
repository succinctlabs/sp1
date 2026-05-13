use super::SyscallRuntime;
use crate::{ExecutionMode, SyscallCode};

pub(crate) fn hint_len_syscall<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    ctx: &mut RT,
    _: SyscallCode,
    _: u64,
    _: u64,
) -> Option<u64> {
    ctx.core_mut().mem_reads().next().map(|mem_value| mem_value.value)
}

pub(crate) fn hint_read_syscall<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    _: SyscallCode,
    ptr: u64,
    len_bytes: u64,
) -> Option<u64> {
    // TODO(rkm): need to add tracing here in the future.
    let len_words = len_bytes.div_ceil(8);
    rt.mw_hint_slice(ptr, len_words as usize);
    None
}
