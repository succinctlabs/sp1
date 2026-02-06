use super::SyscallRuntime;
use crate::SyscallCode;

pub(crate) fn hint_len_syscall<'a, RT: SyscallRuntime<'a>>(
    ctx: &mut RT,
    _: SyscallCode,
    _: u64,
    _: u64,
) -> u64 {
    ctx.core_mut().mem_reads().next().expect("Hint read out of bounds").value
}
