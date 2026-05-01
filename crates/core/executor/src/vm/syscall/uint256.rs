use sp1_curves::edwards::WORDS_FIELD_ELEMENT;

use crate::{
    events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, Uint256MulEvent,
        Uint256MulPageProtRecords,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

/// Check page permissions for uint256 mul. Returns early if permission check fails.
fn trap_uint256_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    x_ptr: u64,
    y_ptr: u64,
) -> (Uint256MulPageProtRecords, Option<TrapError>) {
    let mut ret = Uint256MulPageProtRecords {
        read_y_modulus_page_prot_records: Vec::new(),
        write_x_page_prot_records: Vec::new(),
    };

    let (read_y_modulus_page_prot_records, read_error) =
        rt.read_slice_check(y_ptr, WORDS_FIELD_ELEMENT * 2);
    ret.read_y_modulus_page_prot_records = read_y_modulus_page_prot_records;
    if read_error.is_some() {
        return (ret, read_error);
    }

    rt.increment_clk();
    let (x_page_prot_records, write_error) = rt.read_write_slice_check(x_ptr, 4);
    ret.write_x_page_prot_records = x_page_prot_records;
    if write_error.is_some() {
        return (ret, write_error);
    }

    (ret, None)
}

pub(crate) fn uint256_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let x_ptr = arg1;
    if !x_ptr.is_multiple_of(8) {
        panic!();
    }
    let y_ptr = arg2;
    if !y_ptr.is_multiple_of(8) {
        panic!();
    }

    let clk = rt.core().clk();

    let (page_prot_records, is_trap) = trap_uint256_mul(rt, x_ptr, y_ptr);

    // Default values if trap occurs
    let mut x: Vec<u64> = vec![0; WORDS_FIELD_ELEMENT];
    let mut y: Vec<u64> = vec![0; WORDS_FIELD_ELEMENT];
    let mut modulus: Vec<u64> = vec![0; WORDS_FIELD_ELEMENT];
    let mut y_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut modulus_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut x_memory_records: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        // First read the words for the x value. We can read a slice_unsafe here because we write
        // the computed result to x later.
        x = rt.mr_slice_unsafe(WORDS_FIELD_ELEMENT);

        // Read the y and modulus values.
        let combined_memory_records = rt.mr_slice_without_prot(y_ptr, WORDS_FIELD_ELEMENT * 2);

        let (y_mem, modulus_mem) = combined_memory_records.split_at(WORDS_FIELD_ELEMENT);
        y_memory_records = y_mem.to_vec();
        modulus_memory_records = modulus_mem.to_vec();

        y = y_memory_records.iter().map(|record| record.value).collect();
        modulus = modulus_memory_records.iter().map(|record| record.value).collect();

        rt.increment_clk();

        // Write the result to x and keep track of the memory records.
        x_memory_records = rt.mw_slice_without_prot(x_ptr, 4);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = PrecompileEvent::Uint256Mul(Uint256MulEvent {
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            modulus,
            x_memory_records,
            y_memory_records,
            modulus_memory_records,
            local_mem_access,
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
