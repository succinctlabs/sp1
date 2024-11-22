use num::{BigUint, One, Zero};

use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec, WORD_SIZE};

use crate::{
    events::{PrecompileEvent, Uint256MulEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct AddMulSyscall;

fn execute(
    &self,
    rt: &mut SyscallContext,
    syscall_code: SyscallCode,
    // We can use arg1 to store first pointer, and decode other pointers from memory
    arg1: u32,
    arg2: u32,  // unused but kept for consistency with syscall interface
) -> Option<u32> {
    let clk = rt.clk;

    // arg1 points to a memory location that contains our 4 pointers
    let ptr_base = arg1;
    if ptr_base % 4 != 0 {
        panic!();
    }

    // Read the 4 pointers from memory
    let (_, ptrs) = rt.mr_slice(ptr_base, 4); // Read 4 u32 words containing our pointers
    let a_ptr = ptrs[0];
    let b_ptr = ptrs[1];
    let c_ptr = ptrs[2];
    let d_ptr = ptrs[3];

    // Check alignment for all pointers
    if a_ptr % 4 != 0 || b_ptr % 4 != 0 || c_ptr % 4 != 0 || d_ptr % 4 != 0 {
        panic!();
    }

    // Read all input values with memory records
    let (a_memory_records, a) = rt.mr_slice(a_ptr, WORDS_FIELD_ELEMENT);
    let (b_memory_records, b) = rt.mr_slice(b_ptr, WORDS_FIELD_ELEMENT);
    let (c_memory_records, c) = rt.mr_slice(c_ptr, WORDS_FIELD_ELEMENT);
    let (d_memory_records, d) = rt.mr_slice(d_ptr, WORDS_FIELD_ELEMENT);

    // Convert all inputs to BigUint
    let uint256_a = BigUint::from_bytes_le(&words_to_bytes_le_vec(&a));
    let uint256_b = BigUint::from_bytes_le(&words_to_bytes_le_vec(&b));
    let uint256_c = BigUint::from_bytes_le(&words_to_bytes_le_vec(&c));
    let uint256_d = BigUint::from_bytes_le(&words_to_bytes_le_vec(&d));

    // Perform computations
    let modulus = BigUint::one() << 256; // Use 2^256 as modulus

    // First multiplication: a * b
    let mul1_result = (uint256_a * uint256_b) % &modulus;

    // Second multiplication: c * d
    let mul2_result = (uint256_c * uint256_d) % &modulus;

    // Final addition: (a*b) + (c*d)
    let result = (mul1_result + mul2_result) % modulus;

    // Convert result to bytes and pad
    let mut result_bytes = result.to_bytes_le();
    result_bytes.resize(32, 0u8); // Pad to 32 bytes
    let result_words = bytes_to_words_le::<8>(&result_bytes);

    // Increment clock and write result back to first pointer (a_ptr)
    rt.clk += 1;
    let result_memory_records = rt.mw_slice(a_ptr, &result_words);

    // Record event
    let lookup_id = rt.syscall_lookup_id;
    let shard = rt.current_shard();
    let event = PrecompileEvent::AddMul(AddMulEvent {
        lookup_id,
        shard,
        clk,
        a_ptr,
        b_ptr,
        c_ptr,
        d_ptr,
        a,
        b,
        c,
        d,
        a_memory_records,
        b_memory_records,
        c_memory_records,
        d_memory_records,
        result_memory_records,
        local_mem_access: rt.postprocess(),
    });

    let syscall_event = rt.rt.syscall_event(
        clk,
        syscall_code.syscall_id(),
        arg1,
        arg2,
        lookup_id,
    );
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
