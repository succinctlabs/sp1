use memmap2::MmapMut;
use sp1_jit::{
    memory::AnonymousMemory, trace_capacity, ComputeInstructions, JitContext, MemoryInstructions,
    RiscOperand, RiscRegister, RiscvTranspiler, SystemInstructions,
};

// Import the actual sp1_ecall_handler from the minimal executor
use crate::minimal::ecall::sp1_ecall_handler;

// Helper function to create a new backend for testing
fn new_backend() -> sp1_jit::backends::x86::TranspilerBackend {
    sp1_jit::backends::x86::TranspilerBackend::new(0, 1024 * 2, 1000, 100, 100, 8).unwrap()
}

// Finalize the function and call it.
fn run_test(assembler: sp1_jit::backends::x86::TranspilerBackend) {
    let mut func = assembler.finalize::<AnonymousMemory>().expect("Failed to finalize function");

    let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(1000))).expect("create mmap buf");
    let trace_buf_ptr = trace_buf.as_mut_ptr();

    unsafe {
        func.call(trace_buf_ptr);
    }
}

#[test]
fn test_write_syscall_to_public_values() {
    let mut backend = new_backend();

    backend.register_ecall_handler(sp1_ecall_handler);

    backend.start_instr();

    // FD_PUBLIC_VALUES from sp1_primitives
    const FD_PUBLIC_VALUES: u32 = 13;

    // Store some data at address 0x10
    backend.add(RiscRegister::X1, RiscOperand::Immediate(0x12345678), RiscOperand::Immediate(0));
    backend.sw(RiscRegister::X0, RiscRegister::X1, 0x10);
    backend.add(
        RiscRegister::X1,
        RiscOperand::Immediate(0x9ABCDEF0u32 as i32),
        RiscOperand::Immediate(0),
    );
    backend.sw(RiscRegister::X0, RiscRegister::X1, 0x14);

    // Set up WRITE syscall for public values
    backend.add(RiscRegister::X5, RiscOperand::Immediate(0x02), RiscOperand::Immediate(0));
    backend.add(
        RiscRegister::X10,
        RiscOperand::Immediate(FD_PUBLIC_VALUES as i32),
        RiscOperand::Immediate(0),
    );
    backend.add(RiscRegister::X11, RiscOperand::Immediate(0x10), RiscOperand::Immediate(0));
    backend.add(RiscRegister::X12, RiscOperand::Immediate(8), RiscOperand::Immediate(0)); // 8 bytes

    backend.ecall();

    // Verify the public values were written to the stream
    extern "C" fn check_public_values(ctx: *mut JitContext) {
        let ctx = unsafe { &mut *ctx };
        let public_values = unsafe { ctx.public_values_stream() };
        assert_eq!(public_values.len(), 8);
        // Check the written values (little endian)
        assert_eq!(&public_values[0..4], &0x12345678u32.to_le_bytes());
        assert_eq!(&public_values[4..8], &0x9ABCDEF0u32.to_le_bytes());
    }
    backend.call_extern_fn(check_public_values);

    run_test(backend);
}

#[test]
fn test_write_syscall_to_hint() {
    let mut backend = new_backend();

    backend.register_ecall_handler(sp1_ecall_handler);

    backend.start_instr();

    // FD_HINT from sp1_primitives
    const FD_HINT: u32 = 14;

    // Store hint data at address 0x10
    backend.add(
        RiscRegister::X1,
        RiscOperand::Immediate(0xDEADBEEFu32 as i32),
        RiscOperand::Immediate(0),
    );
    backend.sw(RiscRegister::X0, RiscRegister::X1, 0x10);

    // Set up WRITE syscall for hint buffer
    backend.add(RiscRegister::X5, RiscOperand::Immediate(0x02), RiscOperand::Immediate(0));
    backend.add(
        RiscRegister::X10,
        RiscOperand::Immediate(FD_HINT as i32),
        RiscOperand::Immediate(0),
    );
    backend.add(RiscRegister::X11, RiscOperand::Immediate(0x10), RiscOperand::Immediate(0));
    backend.add(RiscRegister::X12, RiscOperand::Immediate(4), RiscOperand::Immediate(0));

    backend.ecall();

    // Verify the hint was added to the input buffer
    extern "C" fn check_hint_buffer(ctx: *mut JitContext) {
        let ctx = unsafe { &mut *ctx };
        let input_buffer = unsafe { ctx.input_buffer() };
        assert_eq!(input_buffer.len(), 1);
        let hint_data = &input_buffer[0];
        assert_eq!(hint_data.len(), 4);
        assert_eq!(&hint_data[0..4], &0xDEADBEEFu32.to_le_bytes());
    }
    backend.call_extern_fn(check_hint_buffer);

    run_test(backend);
}
