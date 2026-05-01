use crate::{
    events::{PrecompileEvent, SigReturnEvent},
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode,
};

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sig_return<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let clk = rt.core().clk();
    let ptr = arg1;
    assert_eq!(arg1 % 8, 0);
    assert_eq!(arg2, 0);

    let memory_read_records = rt.mr_slice_without_prot(ptr + 8, 31);
    rt.increment_clk();

    let mut register_write_records = Vec::new();
    for (i, record) in memory_read_records.iter().enumerate() {
        register_write_records.push(rt.rw(i + 1, record.value));
    }

    let x5_value = memory_read_records[4].value;

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Create and add the event
        let event = PrecompileEvent::SigReturn(SigReturnEvent {
            clk,
            ptr,
            memory_read_records,
            register_write_records,
            local_mem_access,
            local_page_prot_access,
        });

        // Here, it's ok to put `None` as the `pc` reading record.
        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            None,
        );

        rt.add_precompile_event(syscall_code, syscall_event, event);
    }

    Some(x5_value)
}
