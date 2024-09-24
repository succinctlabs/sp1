use num::{BigUint, Integer, One};

// use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec};

use crate::{
    events::U256xU2048MulEvent,
    syscalls::{Syscall, SyscallContext},
};

pub(crate) struct U256xU2048MulSyscall;

impl Syscall for U256xU2048MulSyscall {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let clk = rt.clk;

        let a_ptr = arg1;
        let b_ptr = arg2;

        let (r3, arg3) = rt.mr(crate::Register::X12 as u32);
        let (r4, arg4) = rt.mr(crate::Register::X13 as u32);

        let (a_memory_records, a) = rt.mr_slice(a_ptr, 8);
        let (b_memory_records, b) = rt.mr_slice(b_ptr, 64);
        let uint256_a = BigUint::from_bytes_le(&words_to_bytes_le_vec(&a));
        let uint2048_b = BigUint::from_bytes_le(&words_to_bytes_le_vec(&b));

        let result = uint256_a * uint2048_b;

        let two_to_2048 = BigUint::one() << 2048;

        let (hi, lo) = result.div_rem(&two_to_2048);

        let mut lo_bytes = lo.to_bytes_le();
        lo_bytes.resize(256, 0u8);
        let lo_words = bytes_to_words_le::<64>(&lo_bytes);

        let mut hi_bytes = hi.to_bytes_le();
        hi_bytes.resize(32, 0u8);
        let hi_words = bytes_to_words_le::<8>(&hi_bytes);

        // Increment clk so that the write is not at the same cycle as the read.
        rt.clk += 1;

        let lo_memory_records = rt.mw_slice(arg3, &lo_words);
        let hi_memory_records = rt.mw_slice(arg4, &hi_words);
        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut().u256x2048_mul_events.push(U256xU2048MulEvent {
            lookup_id,
            shard,
            channel,
            clk,
            a_ptr,
            a,
            b_ptr,
            b,
            lo_ptr: arg3,
            lo: lo_words.to_vec(),
            hi_ptr: arg4,
            hi: hi_words.to_vec(),
            lo_ptr_memory: r3,
            hi_ptr_memory: r4,
            a_memory_records,
            b_memory_records,
            lo_memory_records,
            hi_memory_records,
        });

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
