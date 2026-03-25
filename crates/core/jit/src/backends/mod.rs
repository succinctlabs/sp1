pub mod debug;
pub use debug::DebugBackend;

#[cfg(sp1_native_executor_available)]
pub mod x86;
#[cfg(sp1_native_executor_available)]
pub use x86::TranspilerBackend;

/// Calculates trace buf capacity size assuming it will be 90% full before exiting
pub fn trace_capacity(max_trace_size: Option<u64>) -> usize {
    let max_trace_size = max_trace_size.unwrap_or(0) as usize;

    if max_trace_size == 0 {
        0
    } else {
        // Allocate a trace buffer with enough headroom for the worst-case single-instruction
        // overflow. The chunk-stop check only runs between instructions, so a precompile ecall
        // can emit up to ~288 trace entries (sha256_extend) beyond max_trace_size.
        const MAX_SINGLE_INSTRUCTION_MEM_OPS: usize = 512;

        let event_bytes = max_trace_size * std::mem::size_of::<crate::MemValue>();
        // Scale by 10/9 for proportional leeway on large traces.
        let event_bytes = event_bytes * 10 / 9;
        // Add fixed headroom for worst-case single-instruction overflow.
        let worst_case_bytes =
            MAX_SINGLE_INSTRUCTION_MEM_OPS * std::mem::size_of::<crate::MemValue>();
        let header_bytes = std::mem::size_of::<crate::TraceChunkHeader>();
        event_bytes + worst_case_bytes + header_bytes
    }
}
