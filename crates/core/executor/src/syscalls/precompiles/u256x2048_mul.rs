use num::{BigUint, Integer, One};

use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec, WORD_SIZE};

use crate::{
    events::{MemoryAccessPosition, Uint256MulEvent},
    syscalls::{Syscall, SyscallContext},
};

pub(crate) struct U256xU2048MulSyscall;

impl Syscall for U256xU2048MulSyscall {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        // let clk = rt.clk;

        let a_ptr = arg1;
        // if x_ptr % 4 != 0 {
        //     panic!();
        // }
        let b_ptr = arg2;
        // if y_ptr % 4 != 0 {
        //     panic!();
        // }

        let arg3 = rt.rt.rr(crate::Register::X12, MemoryAccessPosition::Memory);
        let arg4 = rt.rt.rr(crate::Register::X13, MemoryAccessPosition::Memory);
        // println!("arg1: {arg1}");
        // println!("arg2: {arg2}");
        // println!("arg3: {arg3}");
        // println!("arg4: {arg4}");

        // // First read the words for the x value. We can read a slice_unsafe here because we write
        // // the computed result to x later.
        let a = rt.slice_unsafe(a_ptr, 8);
        let b = rt.slice_unsafe(b_ptr, 64);
        let uint256_a = BigUint::from_bytes_le(&words_to_bytes_le_vec(&a));
        let uint2048_b = BigUint::from_bytes_le(&words_to_bytes_le_vec(&b));
        // println!("a: {:?}", a);
        // println!("b: {:?}", b);
        // println!("uint256_a: {}", uint256_a);
        // println!("uint2048_b: {}", uint2048_b);

        let result = uint256_a * uint2048_b;

        let two_to_2048 = BigUint::one() << 2048;

        // let hi: BigUint = &result / &two_to_2048;
        // let lo: BigUint = &result % &two_to_2048;

        let (hi, lo) = result.div_rem(&two_to_2048);
        // println!("computed hi: {hi}");
        // println!("computed lo: {lo}");

        let mut lo_bytes = lo.to_bytes_le();
        lo_bytes.resize(256, 0u8);
        let lo_words = bytes_to_words_le::<64>(&lo_bytes);

        let mut hi_bytes = hi.to_bytes_le();
        hi_bytes.resize(32, 0u8);
        let hi_words = bytes_to_words_le::<8>(&hi_bytes);

        // Increment clk so that the write is not at the same cycle as the read.
        rt.clk += 1;

        rt.mw_slice(arg3, &lo_words);
        rt.mw_slice(arg4, &hi_words);
        // let lookup_id = rt.syscall_lookup_id;
        // let shard = rt.current_shard();
        // let channel = rt.current_channel();
        // rt.record_mut().uint256_mul_events.push(Uint256MulEvent {
        //     lookup_id,
        //     shard,
        //     channel,
        //     clk,
        //     x_ptr,
        //     x,
        //     y_ptr,
        //     y,
        //     modulus,
        //     x_memory_records,
        //     y_memory_records,
        //     modulus_memory_records,
        // });

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
