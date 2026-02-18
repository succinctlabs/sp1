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
            CrashEventResult::Handled(true)
        }
    }
}

#[cfg(sp1_use_native_executor)]
fn main() {
    use serde::{Deserialize, Serialize};
    use sp1_core_executor::{MinimalTranspiler, Program, HALT_PC};
    use sp1_jit::{memory::SharedMemory, shm::ShmTraceRing, trace_capacity};
    use std::{
        collections::VecDeque,
        io::{self, BufReader, BufWriter, Write},
        ops::DerefMut,
        sync::Arc,
    };
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Input {
        pub program: Arc<Program>,
        pub is_debug: bool,
        pub max_trace_size: Option<u64>,
        pub input: VecDeque<Vec<u8>>,
        pub shm_slot_size: usize,
        pub id: String,
        pub max_memory_size: usize,
        pub memory_limit: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Output {
        pub public_values_stream: Vec<u8>,
        pub hints: Vec<(u64, Vec<u8>)>,
        pub global_clk: u64,
        pub exit_code: u32,
    }

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
            unsafe {
                compiled.call(guard.deref_mut().as_mut_ptr());
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
