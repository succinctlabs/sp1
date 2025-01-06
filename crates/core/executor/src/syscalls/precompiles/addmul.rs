use num::{BigUint, One, Zero};

use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec, WORD_SIZE};

use crate::{
    events::{PrecompileEvent, AddMulEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    Register::{X12, X13, X14},
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
    let a_ptr = arg1;
    let b_ptr = arg2;
    let (c_ptr_memory, c_ptr) = rt.mr(X12 as u32);
    let (d_ptr_memory, d_ptr) = rt.mr(X13 as u32);
    let (e_ptr_memory, e_ptr) = rt.mr(X14 as u32);
    rt.clk += 1;
    let (a_memory_records, a) = rt.mr(a_ptr);
    let (b_memory_records, b) = rt.mr(b_ptr);
    let (c_memory_records, c) = rt.mr(c_ptr);
    let (d_memory_records, d) = rt.mr(d_ptr);

    println!("a: {}", a);
    println!("b: {}", b);
    println!("c: {}", c);
    println!("d: {}", d);
    println!("a_memory_records: {:?}", a_memory_records);
    println!("c_ptr_memory: {:?}", c_ptr_memory);
    // Perform computations
    //let modulus = BigUint::one() << 256; // Use 2^256 as modulus

    // First multiplication: a * b
    let mul1_result = a * b;

    // Second multiplication: c * d
    let mul2_result = c * d;

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

    // let mut result_bytes = result.to_le_bytes().to_vec();
    // result_bytes.resize(32, 0u8); 
    // let result_words = bytes_to_words_le::<8>(&result_bytes);
    rt.clk += 1;
    let e = result;
    let e_memory_records = rt.mw(e_ptr, e);
    println!("e_memory_records: {:?}", e_memory_records);

    let shard = rt.current_shard();
    let event = PrecompileEvent::ADDMul(AddMulEvent {
        lookup_id,
        shard,
        clk,
        a,
        b,
        c,
        d,
        e,
        a_ptr,
        b_ptr,
        c_ptr,
        d_ptr,
        e_ptr,
        a_memory_records,
        b_memory_records,
        c_memory_records,
        d_memory_records,
        e_memory_records,
        c_ptr_memory,
        d_ptr_memory,
        e_ptr_memory,
        local_mem_access: rt.postprocess(),
    });

    let syscall_event = rt.rt.syscall_event(
        clk,
        syscall_code.syscall_id(),
        arg1,
        arg2,
        lookup_id,
    );

    // Convert result to bytes and pad
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}

fn num_extra_cycles(&self) -> u32 {
    1
}
}
