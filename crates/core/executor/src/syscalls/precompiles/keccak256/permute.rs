use crate::{
    events::{KeccakPermuteEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 32 bits, so it is 50 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE * 2;

pub(crate) struct Keccak256PermuteSyscall;

impl Syscall for Keccak256PermuteSyscall {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let state_ptr = arg1;
        if arg2 != 0 {
            panic!("Expected arg2 to be 0, got {arg2}");
        }

        let mut state_read_records = Vec::new();
        let mut state_write_records = Vec::new();

        let mut state = Vec::new();

        let (state_records, state_values) = rt.mr_slice(state_ptr, STATE_NUM_WORDS);
        state_read_records.extend_from_slice(&state_records);

        for values in state_values.chunks_exact(2) {
            let least_sig = values[0];
            let most_sig = values[1];
            state.push(least_sig as u64 + ((most_sig as u64) << 32));
        }

        let saved_state = state.clone();

        let mut state = state.try_into().unwrap();
        keccakf(&mut state);

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        rt.clk += 1;
        let mut values_to_write = Vec::new();
        for i in 0..STATE_SIZE {
            let most_sig = ((state[i] >> 32) & 0xFFFFFFFF) as u32;
            let least_sig = (state[i] & 0xFFFFFFFF) as u32;
            values_to_write.push(least_sig);
            values_to_write.push(most_sig);
        }

        let write_records = rt.mw_slice(state_ptr, values_to_write.as_slice());
        state_write_records.extend_from_slice(&write_records);

        // Push the Keccak permute event.
        let shard = rt.current_shard();
        let lookup_id = rt.syscall_lookup_id;
        let event = PrecompileEvent::KeccakPermute(KeccakPermuteEvent {
            lookup_id,
            shard,
            clk: start_clk,
            pre_state: saved_state.as_slice().try_into().unwrap(),
            post_state: state.as_slice().try_into().unwrap(),
            state_read_records,
            state_write_records,
            state_addr: state_ptr,
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(start_clk, syscall_code.syscall_id(), arg1, arg2, lookup_id);
        rt.record_mut().add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
