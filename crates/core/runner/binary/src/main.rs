#[cfg(not(sp1_use_native_executor))]
fn main() {}

#[cfg(sp1_use_native_executor)]
pub mod signal {
    use crash_handler::{CrashContext, CrashEvent, CrashEventResult};
    use sp1_jit::shm::ShmTraceRing;

    pub struct CrashReporter {
        pub ring: ShmTraceRing,
    }

    unsafe impl CrashEvent for CrashReporter {
        fn on_crash(&self, context: &CrashContext) -> CrashEventResult {
            // Extract info
            let sig = context.siginfo.ssi_signo as i32;
            let addr = context.siginfo.ssi_addr;
            let code = context.siginfo.ssi_code;

            // --- DEFINE MISSING CONSTANTS MANUALLY ---
            // These are standard POSIX values for x86/ARM Linux & macOS.
            const SEGV_MAPERR: i32 = 1; // Address not mapped to object
            const SEGV_ACCERR: i32 = 2; // Invalid permissions for mapped object

            // Hint: 2 = Write (if SEGV_ACCERR), 1 = Read (if SEGV_MAPERR, very likely), 0 = Unknown
            let op_hint = match (sig, code) {
                (libc::SIGSEGV, SEGV_ACCERR) => 2,
                (libc::SIGSEGV, SEGV_MAPERR) => 1,
                _ => 0,
            };

            eprintln!("[CrashHandler] CAUGHT SIGNAL {} at 0x{:x}", sig, addr);

            // Direct access to the ring! No global statics needed.
            self.ring.notify_crash(sig, addr, op_hint);

            // Tell crash-handler to proceed with the next handler (or default behavior)
            CrashEventResult::Handled(false)
        }
    }
}

#[cfg(sp1_use_native_executor)]
fn main() {
    use sp1_core_executor::{MinimalTranspiler, HALT_PC};
    use sp1_core_executor_runner_binary::{Input, Output};
    use sp1_jit::{memory::SharedMemory, shm::ShmTraceRing, trace_capacity, TraceChunkHeader};
    use std::{
        io::{self, BufReader, BufWriter, Write},
        ops::DerefMut,
    };
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // Stdin accepts input, stdout emits output, stderr handles all logging.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off")))
        .with(
            fmt::layer()
                .with_writer(io::stderr)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(false)
                .compact(),
        )
        .init();

    let mut reader = BufReader::new(io::stdin().lock());
    let input: Input = bincode::deserialize_from(&mut reader).expect("deserializing input");

    let transpiler =
        MinimalTranspiler::new(input.max_memory_size, input.is_debug, input.max_trace_size);
    let mut compiled = transpiler.transpile::<SharedMemory>(input.program.as_ref());
    compiled.memory.open_readwrite(&input.id).expect("initialize memory");
    compiled.with_initial_memory_image(input.program.memory_image.clone());
    compiled.set_input_buffer(input.input.clone());

    if transpiler.tracing() {
        // Tracing mode is on
        let trace_buf_size = trace_capacity(input.max_trace_size);
        let producer = ShmTraceRing::open(&input.id, input.shm_slot_size, trace_buf_size)
            .expect("open shm file");
        // Setup signal handler
        let _handler = crash_handler::CrashHandler::attach(Box::new(signal::CrashReporter {
            ring: producer.clone(),
        }));

        while compiled.pc != HALT_PC {
            let mut guard = producer.acquire();
            let ptr = guard.deref_mut().as_mut_ptr();
            unsafe {
                // In ring buffer setup we are reusing previous memory, we cannot make sure
                // all memory is zero, but we need to set TraceChunkHeader to 0 values.
                std::ptr::write_bytes(ptr as *mut TraceChunkHeader, 0, 1);
                compiled.call(ptr);
            }
        }

        producer.mark_finished();
    } else {
        // Tracing mode is off, we only need to call once.
        unsafe {
            compiled.call(std::ptr::null_mut());
        }
        assert_eq!(compiled.pc, HALT_PC);
    }

    let output = Output {
        public_values_stream: compiled.public_values_stream,
        hints: compiled.hints,
        global_clk: compiled.global_clk,
        exit_code: compiled.exit_code,
    };

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    bincode::serialize_into(&mut writer, &output).expect("serialize output");
    writer.flush().expect("flush");
}
