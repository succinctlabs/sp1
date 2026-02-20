use base64::{engine::general_purpose::URL_SAFE, Engine};
use sp1_core_executor::{
    ExecutionError, MinimalTranspiler, Opcode, Program, UnsafeMemory, DEFAULT_MEMORY_LIMIT,
    DEFAULT_TRACE_CHUNK_SLOTS,
};
use sp1_core_executor_runner_binary::{Input, Output};
use sp1_jit::{
    memory::SharedMemory,
    shm::{ShmTraceRing, TraceResult},
    trace_capacity, MemValue, TraceChunkRaw,
};
use sp1_primitives::consts::MAX_JIT_LOG_ADDR;
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, BufWriter, Write},
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    ptr::NonNull,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use sysinfo::{Pid, System};

const MEMORY_MONITOR_INTERAL_MILLIS: u64 = 100;
const CONSUMER_TIMEOUT_MILLIS: u64 = 100;

/// Minimal trace native executor that runs SP1 program in child process
pub struct MinimalExecutorRunner {
    input: Input,

    memory: SharedMemory,
    consumer: Option<ShmTraceRing>,

    process: Option<(Child, JoinHandle<()>)>,
    output: Option<Result<Output, ExecutionError>>,
}

impl MinimalExecutorRunner {
    /// Create a new minimal executor and transpile the program.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute.
    /// * `is_debug` - Whether to compile the program with debugging.
    /// * `max_trace_size` - The maximum trace size in terms of [`MemValue`]s. If not set tracing
    ///   will be disabled.
    /// * `memory_limit` - The memory limit bytes. If not set, the default value(24 GB) will be used.
    /// * `shm_slot_size` - Share trace ring buffer slot size
    #[must_use]
    pub fn new(
        program: Arc<Program>,
        is_debug: bool,
        max_trace_size: Option<u64>,
        memory_limit: u64,
        shm_slot_size: usize,
    ) -> Self {
        let id = format!("sp1_{}", URL_SAFE.encode(uuid::Uuid::new_v4().as_bytes()));
        let input = Input {
            program,
            is_debug,
            max_trace_size,
            input: VecDeque::new(),
            shm_slot_size,
            id,
            max_memory_size: 2_u64.pow(MAX_JIT_LOG_ADDR as u32) as usize,
            memory_limit,
        };
        let (memory, consumer) = create(&input);

        Self { input, consumer, memory, process: None, output: None }
    }

    /// Create a new minimal executor with no tracing or debugging.
    #[must_use]
    pub fn simple(program: Arc<Program>) -> Self {
        // When no tracing is on, we don't need SHM slots.
        Self::new(program, false, None, DEFAULT_MEMORY_LIMIT, 0)
    }

    /// Create a new tracing minimal executor with default configs
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute.
    /// * `max_trace_size` - The maximum trace size in terms of [`MemValue`]s. If not set, it will
    ///   be set to 2 gb worth of memory events.
    #[must_use]
    pub fn simple_tracing(program: Arc<Program>, max_trace_size: u64) -> Self {
        Self::new(
            program,
            false,
            Some(max_trace_size),
            DEFAULT_MEMORY_LIMIT,
            DEFAULT_TRACE_CHUNK_SLOTS,
        )
    }

    /// Create a new minimal executor with debugging.
    #[must_use]
    pub fn debug(program: Arc<Program>) -> Self {
        // When no tracing is on, we don't need SHM slots.
        Self::new(program, true, None, DEFAULT_MEMORY_LIMIT, 0)
    }

    /// Add input to the executor.
    pub fn with_input(&mut self, input: &[u8]) {
        // Input can only be added when process hasn't been started yet.
        assert!(self.process.is_none());
        self.input.input.push_back(input.to_vec());
    }

    /// Execute the program. Returning a trace chunk if the program has not completed.
    pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
        self.try_execute_chunk().expect("execute chunk")
    }

    /// Try executing the program, when errors happen, returns ExecutionError with more
    /// diagnosis information.
    pub fn try_execute_chunk(&mut self) -> Result<Option<TraceChunkRaw>, ExecutionError> {
        match &self.output {
            Some(Ok(_)) => return Ok(None),
            Some(Err(e)) => return Err(e.clone()),
            None => (),
        }

        if self.process.is_none() {
            // Start the process
            let mut child = spawn_restricted(
                Command::new(crate::binary::get_binary_path()),
                self.input.memory_limit,
            )
            .expect("start child proces");

            {
                let stdin = child.stdin.take().expect("open stdin");
                let mut writer = BufWriter::new(stdin);
                bincode::serialize_into(&mut writer, &self.input).expect("sending input");
                writer.flush().expect("flushing input");
            }

            let stderr = child.stderr.take().expect("open stderr");
            let id = self.input.id.clone();
            let log_handle = thread::spawn(move || {
                let reader = BufReader::new(stderr);
                use BufRead;
                for l in reader.lines().map_while(Result::ok) {
                    tracing::debug!("CHILD {}: {}", id, l);
                }
            });

            self.process = Some((child, log_handle));
        }

        if let Some(consumer) = &self.consumer {
            // Looking for the next chunk
            loop {
                match consumer.access(Duration::from_millis(CONSUMER_TIMEOUT_MILLIS)) {
                    TraceResult::Data(guard) => {
                        return Ok(Some(unsafe { TraceChunkRaw::from_shm(guard) }));
                    }
                    TraceResult::Finished => {
                        self.wait_for_success();
                        return Ok(None);
                    }
                    TraceResult::Crashed(details) => {
                        // Process logs, they might provide insight into why the program crashed.
                        self.process
                            .take()
                            .unwrap()
                            .1
                            .join()
                            .expect("wait for log thread to finish");
                        let opcode = match details.signal {
                            1 => Opcode::LD,
                            2 => Opcode::SD,
                            _ => Opcode::UNIMP,
                        };
                        let error = match details.signal {
                            libc::SIGSEGV => {
                                ExecutionError::InvalidMemoryAccess(opcode, details.addr)
                            }
                            _ => ExecutionError::Other(format!(
                                "Child native executor crashed, details: {details:?}"
                            )),
                        };

                        self.output = Some(Err(error.clone()));
                        return Err(error);
                    }
                    TraceResult::Timeout => {
                        // Consumer times out, we will need to check if child process is still running.
                        if let Some(status) =
                            self.process.as_mut().unwrap().0.try_wait().expect("try wait")
                        {
                            // We still want to process logs
                            self.process
                                .take()
                                .unwrap()
                                .1
                                .join()
                                .expect("wait for log thread to finish");
                            // Child process is terminated, let's find out why
                            if status.signal() == Some(libc::SIGBUS) {
                                tracing::warn!("SIGBUS signal is received, there is a chance /dev/shm is full!");
                            }
                            let error = match (status.code(), status.signal()) {
                                (_, Some(libc::SIGKILL)) => ExecutionError::TooMuchMemory(),
                                (code, signal) => ExecutionError::Other(format!("Child native executor terminates early, code: {code:?}, signal: {signal:?}")),
                            };
                            self.output = Some(Err(error.clone()));
                            return Err(error);
                        }
                        std::hint::spin_loop();
                    }
                }
            }
        } else {
            // Tracing mode is disabled, wait for process termination
            self.wait_for_success();
            Ok(None)
        }
    }

    fn wait_for_success(&mut self) {
        // SP1 program terminates, wait for output and terminate child process.
        let (mut child, log_thread) = self.process.take().unwrap();
        let stdout = child.stdout.take().expect("open stdout");
        let mut stdout_reader = BufReader::new(stdout);

        let output: Output = bincode::deserialize_from(&mut stdout_reader).expect("read output");
        let status = child.wait().expect("wait for child to exit");
        log_thread.join().expect("wait for log thread to finish");
        // Normal termination, this should just return success.
        assert!(status.success());

        self.output = Some(Ok(output));
    }

    fn output(&self) -> &Output {
        self.output
            .as_ref()
            .expect("Process is still running")
            .as_ref()
            .expect("Process terminated with error state")
    }

    fn take_output(self) -> Output {
        self.output.expect("Process is still running").expect("Process terminated with error state")
    }

    /// Get the registers of the JIT function.
    #[must_use]
    pub fn registers(&self) -> [u64; 32] {
        todo!()
    }

    /// Get the program counter of the JIT function.
    #[must_use]
    pub fn pc(&self) -> u64 {
        todo!()
    }

    /// Check if the program has halted.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.output.is_some()
    }

    /// Get the current value at an address.
    #[must_use]
    pub fn get_memory_value(&self, addr: u64) -> MemValue {
        unsafe { self.unsafe_memory().get(addr) }
    }

    /// Get the program of the JIT function.
    #[must_use]
    pub fn program(&self) -> Arc<Program> {
        self.input.program.clone()
    }

    /// Get the current clock of the JIT function.
    ///
    /// This clock is incremented by 8 or 256 depending on the instruction.
    #[must_use]
    pub fn clk(&self) -> u64 {
        todo!()
    }

    /// Get the global clock of the JIT function.
    ///
    /// This clock is incremented by 1 per instruction.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        self.output().global_clk
    }

    /// Get the exit code of the JIT function.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        self.output().exit_code
    }

    /// Get the public values stream of the JIT function.
    #[must_use]
    pub fn public_values_stream(&self) -> &Vec<u8> {
        &self.output().public_values_stream
    }

    /// Consume self, and return the public values stream.
    #[must_use]
    pub fn into_public_values_stream(self) -> Vec<u8> {
        self.take_output().public_values_stream
    }

    /// Get the hints of the JIT function.
    #[must_use]
    pub fn hints(&self) -> &[(u64, Vec<u8>)] {
        &self.output().hints
    }

    /// Get the lengths of all the hints.
    #[must_use]
    pub fn hint_lens(&self) -> Vec<usize> {
        self.output().hints.iter().map(|(_, hint)| hint.len()).collect()
    }

    /// Get an unsafe memory view of the JIT function.
    ///
    /// This allows reading without lifetime and mutability constraints.
    #[must_use]
    #[allow(clippy::cast_ptr_alignment)]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        let entry_ptr = self.memory.as_ptr() as *mut MemValue;
        UnsafeMemory::new(NonNull::new(entry_ptr).unwrap())
    }

    pub fn reset(&mut self) {
        if let Some((mut child, _)) = self.process.take() {
            child.kill().expect("running child cannot be killed");
        }
        self.output = None;

        let (memory, consumer) = create(&self.input);
        self.memory = memory;
        self.consumer = consumer;
    }
}

// Create partial field variables, so the common logic can be shared
// between `MinimalExecutor::new` and `MinimalExecutor::reset`.
fn create(input: &Input) -> (SharedMemory, Option<ShmTraceRing>) {
    let transpiler =
        MinimalTranspiler::new(input.max_memory_size, input.is_debug, input.max_trace_size);
    let memory_buffer_size = transpiler.memory_buffer_size();
    let memory = SharedMemory::create_readonly(&input.id, memory_buffer_size)
        .expect("create shm file for memory");

    let trace_buf_size = trace_capacity(input.max_trace_size);
    let consumer = if trace_buf_size > 0 {
        Some(
            ShmTraceRing::create(&input.id, input.shm_slot_size, trace_buf_size)
                .expect("create shm file for traces"),
        )
    } else {
        None
    };

    (memory, consumer)
}

/// Spawns a process with piped I/O and an RSS memory monitor thread.
/// **Written by Gemini 3**
fn spawn_restricted(mut cmd: Command, limit_bytes: u64) -> std::io::Result<Child> {
    // Force pipes for all three standard streams
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    // Disable core dump for the child process for fast exiting, in debugging sessions
    // you can comment this section out.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // Create a limit structure with soft and hard limits set to 0
            let limit = libc::rlimit {
                rlim_cur: 0, // Soft limit
                rlim_max: 0, // Hard limit
            };

            // Call setrlimit to disable core dumps
            let ret = libc::setrlimit(libc::RLIMIT_CORE, &limit);

            if ret != 0 {
                // Convert libc error to Rust io::Error
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    // Spawn the child normally using Rust std
    let child = cmd.spawn()?;
    let child_pid = child.id();

    // Start the Background Memory Monitor (The Enforcer)
    thread::spawn(move || {
        let mut sys = System::new();
        let pid = Pid::from_u32(child_pid);
        let poll_interval = Duration::from_millis(MEMORY_MONITOR_INTERAL_MILLIS);

        loop {
            // Refresh only this specific process for performance
            if !sys.refresh_process(pid) {
                break; // Process is finished or gone
            }

            if let Some(proc) = sys.process(pid) {
                // .memory() returns the Resident Set Size (RSS) in bytes
                let current_rss = proc.memory();

                if current_rss > limit_bytes {
                    tracing::warn!(
                        "Monitor: PID {} exceeded limit ({} MB > {} MB). Sending SIGKILL.",
                        child_pid,
                        current_rss / 1024 / 1024,
                        limit_bytes / 1024 / 1024
                    );

                    // Kill the process immediately
                    unsafe {
                        libc::kill(child_pid as i32, libc::SIGKILL);
                    }
                    break;
                }
            }
            thread::sleep(poll_interval);
        }
    });
    Ok(child)
}
