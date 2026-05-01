use crate::{
    events::{
        KeccakPermuteEvent, KeccakPermutePageProtRecords, MemoryReadRecord, MemoryWriteRecord,
        PrecompileEvent,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

pub(crate) const STATE_SIZE: usize = 25;
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

/// Check page permissions for keccak permute. Returns early if permission check fails.
fn trap_keccak256_permute<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    state_ptr: u64,
) -> (KeccakPermutePageProtRecords, Option<TrapError>) {
    let mut ret = KeccakPermutePageProtRecords {
        read_pre_state_page_prot_records: Vec::new(),
        write_post_state_page_prot_records: Vec::new(),
    };

    let (state_read_page_prot_records, read_error) =
        rt.read_slice_check(state_ptr, STATE_NUM_WORDS);
    ret.read_pre_state_page_prot_records = state_read_page_prot_records;
    if read_error.is_some() {
        return (ret, read_error);
    }

    rt.increment_clk();
    let (state_write_page_prot_records, write_error) =
        rt.write_slice_check(state_ptr, STATE_NUM_WORDS);
    ret.write_post_state_page_prot_records = state_write_page_prot_records;
    if write_error.is_some() {
        return (ret, write_error);
    }

    (ret, None)
}

pub fn keccak256_permute<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let state_ptr = arg1;
    if arg2 != 0 {
        panic!("Expected arg2 to be 0, got {arg2}");
    }

    let start_clk = rt.core().clk();

    let (page_prot_records, is_trap) = trap_keccak256_permute(rt, state_ptr);

    // Default values if trap occurs
    let mut state_read_records: Vec<MemoryReadRecord> = Vec::new();
    let mut state_write_records: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(start_clk);
    if is_trap.is_none() {
        // Read the current state (will be overwritten)
        state_read_records = rt.mr_slice_without_prot(state_ptr, STATE_NUM_WORDS);

        rt.increment_clk();

        // Write the new state (we don't compute the actual result in tracing mode)
        state_write_records = rt.mw_slice_without_prot(state_ptr, STATE_NUM_WORDS);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let post_state: Vec<u64> = state_write_records.iter().map(|record| record.value).collect();
        let pre_state: Vec<u64> = state_read_records.iter().map(|record| record.value).collect();

        let event = KeccakPermuteEvent {
            clk: start_clk,
            pre_state: if pre_state.len() == STATE_SIZE {
                pre_state.as_slice().try_into().unwrap()
            } else {
                [0u64; STATE_SIZE]
            },
            post_state: if post_state.len() == STATE_SIZE {
                post_state.as_slice().try_into().unwrap()
            } else {
                [0u64; STATE_SIZE]
            },
            state_read_records,
            state_write_records,
            state_addr: state_ptr,
            local_mem_access,
            page_prot_records,
            local_page_prot_access,
        };

        let syscall_event = rt.syscall_event(
            start_clk,
            syscall_code,
            arg1,
            arg2,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            is_trap,
        );
        rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::KeccakPermute(event));
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
