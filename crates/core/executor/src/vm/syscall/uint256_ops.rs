use crate::{
    events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, Uint256OpsEvent,
        Uint256OpsPageProtRecords,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

const U256_NUM_WORDS: usize = 4;

/// Check page permissions for uint256 ops. Returns early if permission check fails.
fn trap_uint256_ops<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    a_ptr: u64,
    b_ptr: u64,
    c_ptr: u64,
    d_ptr: u64,
    e_ptr: u64,
) -> (Uint256OpsPageProtRecords, Option<TrapError>) {
    let mut ret = Uint256OpsPageProtRecords {
        read_a_page_prot_records: Vec::new(),
        read_b_page_prot_records: Vec::new(),
        read_c_page_prot_records: Vec::new(),
        write_d_page_prot_records: Vec::new(),
        write_e_page_prot_records: Vec::new(),
    };

    let (a_page_prot_records, a_error) = rt.read_slice_check(a_ptr, U256_NUM_WORDS);
    ret.read_a_page_prot_records = a_page_prot_records;
    if a_error.is_some() {
        return (ret, a_error);
    }

    rt.increment_clk();

    let (b_page_prot_records, b_error) = rt.read_slice_check(b_ptr, U256_NUM_WORDS);
    ret.read_b_page_prot_records = b_page_prot_records;
    if b_error.is_some() {
        return (ret, b_error);
    }

    rt.increment_clk();

    let (c_page_prot_records, c_error) = rt.read_slice_check(c_ptr, U256_NUM_WORDS);
    ret.read_c_page_prot_records = c_page_prot_records;
    if c_error.is_some() {
        return (ret, c_error);
    }

    rt.increment_clk();

    let (d_page_prot_records, d_error) = rt.write_slice_check(d_ptr, 4);
    ret.write_d_page_prot_records = d_page_prot_records;
    if d_error.is_some() {
        return (ret, d_error);
    }

    rt.increment_clk();

    let (e_page_prot_records, e_error) = rt.write_slice_check(e_ptr, 4);
    ret.write_e_page_prot_records = e_page_prot_records;
    if e_error.is_some() {
        return (ret, e_error);
    }

    (ret, None)
}

#[allow(clippy::many_single_char_names)]
pub(crate) fn uint256_ops<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let clk = rt.core().clk();

    let op = syscall_code.uint256_op_map();

    // Read addresses - arg1 and arg2 come from the syscall, others from registers
    let a_ptr = arg1;
    let b_ptr = arg2;
    let c_ptr_memory = rt.rr(12 /* X12 */);
    let d_ptr_memory = rt.rr(13 /* X13 */);
    let e_ptr_memory = rt.rr(14 /* X14 */);
    let c_ptr = c_ptr_memory.value;
    let d_ptr = d_ptr_memory.value;
    let e_ptr = e_ptr_memory.value;

    let (page_prot_records, is_trap) = trap_uint256_ops(rt, a_ptr, b_ptr, c_ptr, d_ptr, e_ptr);

    // Default values if trap occurs
    let mut a: Vec<u64> = Vec::new();
    let mut b: Vec<u64> = Vec::new();
    let mut c: Vec<u64> = Vec::new();
    let mut d: Vec<u64> = Vec::new();
    let mut e: Vec<u64> = Vec::new();
    let mut a_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut b_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut c_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut d_memory_records: Vec<MemoryWriteRecord> = Vec::new();
    let mut e_memory_records: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        // Read input values (8 words = 32 bytes each for uint256) and convert to BigUint
        a_memory_records = rt.mr_slice_without_prot(a_ptr, U256_NUM_WORDS);
        rt.increment_clk();
        a = a_memory_records.iter().map(|record| record.value).collect();
        b_memory_records = rt.mr_slice_without_prot(b_ptr, U256_NUM_WORDS);
        rt.increment_clk();
        b = b_memory_records.iter().map(|record| record.value).collect();
        c_memory_records = rt.mr_slice_without_prot(c_ptr, U256_NUM_WORDS);
        c = c_memory_records.iter().map(|record| record.value).collect();

        rt.increment_clk();

        d_memory_records = rt.mw_slice_without_prot(d_ptr, U256_NUM_WORDS);
        d = d_memory_records.iter().map(|record| record.value).collect();

        rt.increment_clk();

        e_memory_records = rt.mw_slice_without_prot(e_ptr, U256_NUM_WORDS);
        e = e_memory_records.iter().map(|record| record.value).collect();
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = PrecompileEvent::Uint256Ops(Uint256OpsEvent {
            clk,
            op,
            a_ptr,
            a: if a.len() == U256_NUM_WORDS {
                a.try_into().unwrap()
            } else {
                [0u64; U256_NUM_WORDS]
            },
            b_ptr,
            b: if b.len() == U256_NUM_WORDS {
                b.try_into().unwrap()
            } else {
                [0u64; U256_NUM_WORDS]
            },
            c_ptr,
            c: if c.len() == U256_NUM_WORDS {
                c.try_into().unwrap()
            } else {
                [0u64; U256_NUM_WORDS]
            },
            d_ptr,
            d: if d.len() == U256_NUM_WORDS {
                d.try_into().unwrap()
            } else {
                [0u64; U256_NUM_WORDS]
            },
            e_ptr,
            e: if e.len() == U256_NUM_WORDS {
                e.try_into().unwrap()
            } else {
                [0u64; U256_NUM_WORDS]
            },
            c_ptr_memory,
            d_ptr_memory,
            e_ptr_memory,
            a_memory_records,
            b_memory_records,
            c_memory_records,
            d_memory_records,
            e_memory_records,
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
