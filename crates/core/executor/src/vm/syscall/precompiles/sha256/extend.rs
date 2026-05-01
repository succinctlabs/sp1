use sp1_primitives::consts::{LOG_PAGE_SIZE, PROT_READ, PROT_WRITE};

use crate::{
    events::{PrecompileEvent, ShaExtendEvent, ShaExtendMemoryRecords, ShaExtendPageProtRecords},
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

/// Check page permissions for sha256 extend. Returns early if permission check fails.
fn trap_sha256_extend<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    w_ptr: u64,
) -> (ShaExtendPageProtRecords, Option<TrapError>) {
    let mut ret = ShaExtendPageProtRecords {
        initial_page_prot_records: Vec::new(),
        extension_page_prot_records: Vec::new(),
    };

    let (initial_page_prot_records, initial_error) = rt.page_prot_range_check(
        w_ptr >> LOG_PAGE_SIZE,
        (w_ptr + 15 * 8) >> LOG_PAGE_SIZE,
        PROT_READ,
    );
    ret.initial_page_prot_records = initial_page_prot_records;
    if initial_error.is_some() {
        return (ret, initial_error);
    }

    rt.increment_clk();
    let (extension_page_prot_records, extension_error) = rt.page_prot_range_check(
        (w_ptr + 16 * 8) >> LOG_PAGE_SIZE,
        (w_ptr + 63 * 8) >> LOG_PAGE_SIZE,
        PROT_READ | PROT_WRITE,
    );
    ret.extension_page_prot_records = extension_page_prot_records;
    if extension_error.is_some() {
        return (ret, extension_error);
    }

    (ret, None)
}

pub(crate) fn sha256_extend<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let w_ptr = arg1;
    assert!(arg2 == 0, "arg2 must be 0");
    assert!(arg1.is_multiple_of(8));

    let clk = rt.core().clk();

    let (page_prot_records, is_trap) = trap_sha256_extend(rt, w_ptr);

    // Default values if trap occurs
    let mut sha_extend_memory_records = Vec::new();

    if is_trap.is_none() {
        sha_extend_memory_records = Vec::with_capacity(48);
        for i in 16..64 {
            // Read w[i-15].
            let w_i_minus_15_reads = rt.mr_without_prot(w_ptr + (i - 15) * 8);

            // Read w[i-2].
            let w_i_minus_2_reads = rt.mr_without_prot(w_ptr + (i - 2) * 8);

            // Read w[i-16].
            let w_i_minus_16_reads = rt.mr_without_prot(w_ptr + (i - 16) * 8);

            // Read w[i-7].
            let w_i_minus_7_reads = rt.mr_without_prot(w_ptr + (i - 7) * 8);
            // Write w[i].
            let w_i_write = rt.mw_without_prot(w_ptr + i * 8);

            rt.increment_clk();

            sha_extend_memory_records.push(ShaExtendMemoryRecords {
                w_i_minus_15_reads,
                w_i_minus_2_reads,
                w_i_minus_16_reads,
                w_i_minus_7_reads,
                w_i_write,
            });
        }
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Push the SHA extend event.
        #[allow(clippy::default_trait_access)]
        let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
            clk,
            w_ptr,
            local_mem_access,
            memory_records: sha_extend_memory_records,
            page_prot_records,
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
