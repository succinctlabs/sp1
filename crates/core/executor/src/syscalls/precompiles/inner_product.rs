use crate::{
    events::{InnerProductEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};
pub(crate) struct InnerProductSyscall;

impl Syscall for InnerProductSyscall {
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

        // get the length of two vector
        let (a_len_memory, a_len) = rt.mr(a_ptr);
        let (b_len_memory, b_len) = rt.mr(b_ptr); 

        assert_eq!(a_len, b_len, "Vector lengths must be equal for inner product");

        // Read the actual vectors. u32 will be 4 bytes
        let (a_memory_records, a) = rt.mr_slice(a_ptr + 4, a_len as usize);
        let (b_memory_records, b) = rt.mr_slice(b_ptr + 4, b_len as usize);

        // Compute inner product
        let mut result = 0u32;
        for i in 0..a_len as usize {
            result += a[i] * b[i];  // Safe since inputs are in u8 range
        }

        
        rt.clk += 1;
        // write result as u32 into a_ptr
        let result_memory_records = rt.mw(a_ptr, result);

        let shard = rt.current_shard();
        let event = PrecompileEvent::InnerProduct(InnerProductEvent {
            shard,
            clk,
            a_ptr,              // Input pointer for first vector
            a,                  // Actual input data for first vector
            b_ptr,              // Input pointer for second vector
            b,                  // Actual input data for second vector
            result,             // The computed inner product result
            a_len_memory,       // Memory record for reading length of first vector
            b_len_memory,       // Memory record for reading length of second vector
            a_memory_records,   // Memory records for reading first vector
            b_memory_records,   // Memory records for reading second vector
            result_memory_records, // Memory records for writing result
            local_mem_access: rt.postprocess(), // All local memory accesses
        });

        // step1: create a syscall event that captures the basic execution context
        let syscall_event = rt.rt.syscall_event(
            clk,             // Current clock cycle
            None,  //  a_record: Option<MemoryRecordEnum> - memory write record for return value
            None,    // op_a_0: Option<bool> - whether the result is written to register 0
            syscall_code,    // identifier for the syscall
            arg1,            // first input pointer
            arg2,            // second input pointer
            rt.next_pc       // next pc
        );

        // step2: associate this syscall event with precompile-specific event
        rt.add_precompile_event(
            syscall_code,    // Identifies which precompile this is
            syscall_event,   // The basic syscall context we just created
            event            // Your detailed InnerProductEvent with all the computation data
        );

        None
    }
}