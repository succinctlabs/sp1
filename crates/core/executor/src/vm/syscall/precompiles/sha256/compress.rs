use crate::{
    events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, ShaCompressEvent,
        ShaCompressPageProtAccess,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

/// Check page permissions for sha256 compress. Returns early if permission check fails.
fn trap_sha256_compress<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    w_ptr: u64,
    h_ptr: u64,
) -> (ShaCompressPageProtAccess, Option<TrapError>) {
    let mut ret = ShaCompressPageProtAccess {
        h_read_page_prot_records: Vec::new(),
        w_read_page_prot_records: Vec::new(),
        h_write_page_prot_records: Vec::new(),
    };

    let (h_read_page_prot_records, h_read_error) = rt.read_slice_check(h_ptr, 8);
    ret.h_read_page_prot_records = h_read_page_prot_records;
    if h_read_error.is_some() {
        return (ret, h_read_error);
    }

    rt.increment_clk();
    let (w_read_page_prot_records, w_read_error) = rt.read_slice_check(w_ptr, 64);
    ret.w_read_page_prot_records = w_read_page_prot_records;
    if w_read_error.is_some() {
        return (ret, w_read_error);
    }

    rt.increment_clk();
    let (h_write_page_prot_records, h_write_error) = rt.write_slice_check(h_ptr, 8);
    ret.h_write_page_prot_records = h_write_page_prot_records;
    if h_write_error.is_some() {
        return (ret, h_write_error);
    }

    (ret, None)
}

pub(crate) fn sha256_compress<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let w_ptr = arg1;
    let h_ptr = arg2;

    let clk = rt.core().clk();

    let (page_prot_access, is_trap) = trap_sha256_compress(rt, w_ptr, h_ptr);

    // Default values if trap occurs
    let mut h_read_records: Vec<MemoryReadRecord> = Vec::new();
    let mut w_i_read_records: Vec<MemoryReadRecord> = Vec::new();
    let mut h_write_records: Vec<MemoryWriteRecord> = Vec::new();
    let mut hx: Vec<u32> = Vec::new();
    let mut original_w: Vec<u32> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        // Execute the "initialize" phase where we read in the h values.
        h_read_records = rt.mr_slice_without_prot(h_ptr, 8);
        hx = h_read_records.iter().map(|r| r.value as u32).collect::<Vec<_>>();

        rt.increment_clk();
        w_i_read_records = rt.mr_slice_without_prot(w_ptr, 64);
        original_w = w_i_read_records.iter().map(|r| r.value as u32).collect::<Vec<_>>();

        rt.increment_clk();
        h_write_records = rt.mw_slice_without_prot(h_ptr, 8);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Push the SHA compress event.
        let event = PrecompileEvent::ShaCompress(ShaCompressEvent {
            clk,
            w_ptr,
            h_ptr,
            w: original_w,
            h: if hx.len() == 8 { hx.try_into().unwrap() } else { [0u32; 8] },
            h_read_records: if h_read_records.len() == 8 {
                h_read_records.try_into().unwrap()
            } else {
                [MemoryReadRecord::default(); 8]
            },
            w_i_read_records,
            h_write_records: if h_write_records.len() == 8 {
                h_write_records.try_into().unwrap()
            } else {
                [MemoryWriteRecord::default(); 8]
            },
            local_mem_access,
            page_prot_access,
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
