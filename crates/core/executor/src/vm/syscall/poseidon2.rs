use crate::{
    events::{MemoryWriteRecord, PageProtRecord, Poseidon2PrecompileEvent, PrecompileEvent},
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

/// Check page permissions for poseidon2. Returns early if permission check fails.
fn trap_poseidon2<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    ptr: u64,
) -> (Vec<PageProtRecord>, Option<TrapError>) {
    rt.read_write_slice_check(ptr, 8)
}

pub(crate) fn poseidon2<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    assert!(arg2 == 0, "arg2 must be 0");
    assert!(arg1.is_multiple_of(8));

    let clk = rt.core().clk();

    let ptr = arg1;

    let (output_page_prot_records, is_trap) = trap_poseidon2(rt, ptr);

    // Default values if trap occurs
    let mut output_memory_records: Vec<MemoryWriteRecord> = Vec::new();

    if is_trap.is_none() {
        // Read the input values using unsafe read (since we'll overwrite them)
        let _ = rt.mr_slice_unsafe(8);

        // Write the computed results from memory records
        output_memory_records = rt.mw_slice_without_prot(ptr, 8);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Create and add the event
        let event = PrecompileEvent::POSEIDON2(Poseidon2PrecompileEvent {
            clk,
            ptr,
            memory_records: output_memory_records,
            local_mem_access,
            page_prot_records: output_page_prot_records,
            local_page_prot_access,
        });

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            is_trap,
        );

        rt.add_precompile_event(syscall_code, syscall_event, event);
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
