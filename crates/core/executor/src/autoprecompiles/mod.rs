#[derive(Debug)]
pub struct ExecutionRecordSnapshotWithPc {
    pub record: ExecutionRecordSnapshot,
    pub pc: u64,
}

#[derive(Debug)]
/// A snapshot of current state of the execution record
/// The execution record is made of vectors for each type of events, as well as single values
/// The snapshot stores the size of the vectors and the current values of the single values at the time of snapshotting
/// Not all data present in the record is present here, because some fields are guaranteed not to change during the execution of an apc.
pub struct ExecutionRecordSnapshot {
    pub cpu_event_count: u32,
    pub add_events_len: usize,
    pub addw_events_len: usize,
    pub addi_events_len: usize,
    pub mul_events_len: usize,
    pub sub_events_len: usize,
    pub subw_events_len: usize,
    pub bitwise_events_len: usize,
    pub shift_left_events_len: usize,
    pub shift_right_events_len: usize,
    pub divrem_events_len: usize,
    pub lt_events_len: usize,
    pub memory_load_byte_events_len: usize,
    pub memory_load_half_events_len: usize,
    pub memory_load_word_events_len: usize,
    pub memory_load_x0_events_len: usize,
    pub memory_load_double_events_len: usize,
    pub memory_store_byte_events_len: usize,
    pub memory_store_half_events_len: usize,
    pub memory_store_word_events_len: usize,
    pub memory_store_double_events_len: usize,
    pub utype_events_len: usize,
    pub branch_events_len: usize,
    pub jal_events_len: usize,
    pub jalr_events_len: usize,
    pub instruction_fetch_events_len: usize,
    pub instruction_decode_events_len: usize,
    pub global_page_prot_initialize_events_len: usize,
    pub global_page_prot_finalize_events_len: usize,
    pub cpu_local_page_prot_access_len: usize,
    pub precompile_events_len: usize,
    pub global_memory_initialize_events_len: usize,
    pub global_memory_finalize_events_len: usize,
    pub cpu_local_memory_access_len: usize,
    pub syscall_events_len: usize,
    pub apc_events_len: usize,
    pub global_interaction_event_count: u32,
    pub bump_memory_events_len: usize,
    pub bump_state_events_len: usize,
}
