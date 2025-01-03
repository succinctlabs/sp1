use num::{BigUint, One, Zero};

use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec, WORD_SIZE};

use crate::{
    events::{PrecompileEvent, AddMulEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct AddMulSyscall;
impl Syscall for AddMulSyscall {
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
    let (_, a) = rt.mr(a_ptr);
    let (_, b) = rt.mr(b_ptr);
    let (_, c) = rt.mr(c_ptr);
    let (_, d) = rt.mr(d_ptr);

    // Convert all inputs to u32
    let u32_a: u32 = a; // No need for references unless explicitly required
    let u32_b: u32 = b;
    let u32_c: u32 = c;
    let u32_d: u32 = d;

    // Perform computations
    //let modulus = BigUint::one() << 256; // Use 2^256 as modulus

    // First multiplication: a * b
    let mul1_result = u32_a * u32_b;

    // Second multiplication: c * d
    let mul2_result = u32_c * u32_d;

    // Final addition: (a*b) + (c*d)
    let result = mul1_result + mul2_result;

    // // Convert result to bytes and pad
    // let mut result_bytes = result.to_bytes_le();
    // result_bytes.resize(32, 0u8); // Pad to 32 bytes
    // let result_words = bytes_to_words_le::<8>(&result_bytes);

    // // Increment clock and write result back to first pointer (a_ptr)
    // rt.clk += 1;
    // let result_memory_records = rt.mw_slice(a_ptr, &result_words);

    // Record event
    let lookup_id = rt.syscall_lookup_id;
    let shard = rt.current_shard();
    let event = PrecompileEvent::ADDMul(AddMulEvent {
        lookup_id,
        shard,
        clk,
        a,
        b,
        c,
        d,
        a_ptr,
        b_ptr,
        c_ptr,
        d_ptr,
        result,
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

fn num_extra_cycles(&self) -> u32 {
    1
}
}
