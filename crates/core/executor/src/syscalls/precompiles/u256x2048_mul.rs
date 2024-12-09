use num::{BigUint, Integer, One};

use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec};

use crate::{
    events::{PrecompileEvent, U256xU2048MulEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    Register::{X12, X13},
};

const U256_NUM_WORDS: usize = 8;
const U2048_NUM_WORDS: usize = 64;
const U256_NUM_BYTES: usize = U256_NUM_WORDS * 4;
const U2048_NUM_BYTES: usize = U2048_NUM_WORDS * 4;

pub(crate) struct U256xU2048MulSyscall;

impl Syscall for U256xU2048MulSyscall {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let clk = rt.clk;

        let a_ptr = arg1;
        let b_ptr = arg2;

        let (lo_ptr_memory, lo_ptr) = rt.rr_traced(X12);
        let (hi_ptr_memory, hi_ptr) = rt.rr_traced(X13);

        let (a_memory_records, a) = rt.mr_slice(a_ptr, U256_NUM_WORDS);
        let (b_memory_records, b) = rt.mr_slice(b_ptr, U2048_NUM_WORDS);
        let uint256_a = BigUint::from_bytes_le(&words_to_bytes_le_vec(&a));
        let uint2048_b = BigUint::from_bytes_le(&words_to_bytes_le_vec(&b));

        let result = uint256_a * uint2048_b;

        let two_to_2048 = BigUint::one() << 2048;

        let (hi, lo) = result.div_rem(&two_to_2048);

        let mut lo_bytes = lo.to_bytes_le();
        lo_bytes.resize(U2048_NUM_BYTES, 0u8);
        let lo_words = bytes_to_words_le::<U2048_NUM_WORDS>(&lo_bytes);

        let mut hi_bytes = hi.to_bytes_le();
        hi_bytes.resize(U256_NUM_BYTES, 0u8);
        let hi_words = bytes_to_words_le::<U256_NUM_WORDS>(&hi_bytes);

        // Increment clk so that the write is not at the same cycle as the read.
        rt.clk += 1;

        let lo_memory_records = rt.mw_slice(lo_ptr, &lo_words);
        let hi_memory_records = rt.mw_slice(hi_ptr, &hi_words);
        let shard = rt.current_shard();
        let event = PrecompileEvent::U256xU2048Mul(U256xU2048MulEvent {
            shard,
            clk,
            a_ptr,
            a,
            b_ptr,
            b,
            lo_ptr,
            lo: lo_words.to_vec(),
            hi_ptr,
            hi: hi_words.to_vec(),
            lo_ptr_memory,
            hi_ptr_memory,
            a_memory_records,
            b_memory_records,
            lo_memory_records,
            hi_memory_records,
            local_mem_access: rt.postprocess(),
        });

        let sycall_event =
            rt.rt.syscall_event(clk, None, None, syscall_code, arg1, arg2, rt.next_pc);
        rt.add_precompile_event(syscall_code, sycall_event, event);

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
