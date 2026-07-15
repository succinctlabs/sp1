use super::SyscallRuntime;
use crate::{
    events::{HintReadEvent, PrecompileEvent},
    ExecutionMode, SyscallCode,
};

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
    syscall_code: SyscallCode,
    ptr: u64,
    len_bytes: u64,
) -> Option<u64> {
    let clk = rt.core().clk();
    let len_words = len_bytes.div_ceil(8);
    let memory_records = rt.mw_hint_slice(ptr, len_words as usize);

    if RT::TRACING {
        let event =
            PrecompileEvent::HintRead(HintReadEvent { clk, ptr, len_bytes, memory_records });

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            ptr,
            len_bytes,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            None,
        );

        rt.add_precompile_event(syscall_code, syscall_event, event);
    }

    None
}
