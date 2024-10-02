use crate::{
    events::{PrecompileEvent, ShaExtendEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct Sha256ExtendSyscall;

impl Syscall for Sha256ExtendSyscall {
    fn num_extra_cycles(&self) -> u32 {
        48
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let clk_init = rt.clk;
        let w_ptr = arg1;
        assert!(arg2 == 0, "arg2 must be 0");

        let w_ptr_init = w_ptr;
        let mut w_i_minus_15_reads = Vec::new();
        let mut w_i_minus_2_reads = Vec::new();
        let mut w_i_minus_16_reads = Vec::new();
        let mut w_i_minus_7_reads = Vec::new();
        let mut w_i_writes = Vec::new();
        for i in 16..64 {
            // Read w[i-15].
            let (record, w_i_minus_15) = rt.mr(w_ptr + (i - 15) * 4);
            w_i_minus_15_reads.push(record);

            // Compute `s0`.
            let s0 =
                w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

            // Read w[i-2].
            let (record, w_i_minus_2) = rt.mr(w_ptr + (i - 2) * 4);
            w_i_minus_2_reads.push(record);

            // Compute `s1`.
            let s1 =
                w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

            // Read w[i-16].
            let (record, w_i_minus_16) = rt.mr(w_ptr + (i - 16) * 4);
            w_i_minus_16_reads.push(record);

            // Read w[i-7].
            let (record, w_i_minus_7) = rt.mr(w_ptr + (i - 7) * 4);
            w_i_minus_7_reads.push(record);

            // Compute `w_i`.
            let w_i = s1.wrapping_add(w_i_minus_16).wrapping_add(s0).wrapping_add(w_i_minus_7);

            // Write w[i].
            w_i_writes.push(rt.mw(w_ptr + i * 4, w_i));
            rt.clk += 1;
        }

        // Push the SHA extend event.
        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
            lookup_id,
            shard,
            clk: clk_init,
            w_ptr: w_ptr_init,
            w_i_minus_15_reads,
            w_i_minus_2_reads,
            w_i_minus_16_reads,
            w_i_minus_7_reads,
            w_i_writes,
            local_mem_access: rt.postprocess(),
        });
        let syscall_event =
            rt.rt.syscall_event(clk_init, syscall_code.syscall_id(), arg1, arg2, lookup_id);
        rt.record_mut().add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
