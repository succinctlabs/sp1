use crate::{
    events::{MProtectEvent, PrecompileEvent},
    memory::MAX_LOG_ADDR,
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode,
};

use sp1_primitives::consts::{PAGE_SIZE, PERMITTED_PROTS};

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn mprotect<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    addr: u64,
    prot: u64,
) -> Option<u64> {
    let prot: u8 = prot.try_into().expect("prot must be 8 bits");

    assert!(addr.is_multiple_of(PAGE_SIZE as u64), "addr must be page aligned");
    assert!(addr < 1 << MAX_LOG_ADDR, "addr must be less than 2^48");
    assert!(PERMITTED_PROTS.contains(&prot), "prot must be a permitted combination");

    let page_idx = addr / PAGE_SIZE as u64;

    rt.page_prot_write(page_idx, prot);

    if RT::TRACING {
        let clk = rt.core().clk();
        let (_, local_page_prot_access) = rt.postprocess_precompile();
        let mprotect_event = MProtectEvent { addr, local_page_prot_access };

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            addr,
            prot as u64,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            None,
        );

        rt.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Mprotect(mprotect_event),
        );
    }

    None
}
