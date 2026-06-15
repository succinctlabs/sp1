use base64::{engine::general_purpose::URL_SAFE, Engine};
use sp1_core_executor::{
    ExecutionError, MinimalTranspiler, Opcode, Program, UnsafeMemory, DEFAULT_MEMORY_LIMIT,
    DEFAULT_TRACE_CHUNK_SLOTS,
};
use sp1_core_executor_runner_binary::{Input, Output};
use sp1_jit::{
    memory::SharedMemory,
    shm::{ShmTraceRing, TraceResult},
    trace_capacity, MemValue, MinimalTrace, TraceChunkRaw,
};
use sp1_primitives::consts::MAX_JIT_LOG_ADDR;
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, BufWriter, Write},
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
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

    // The flag is set by the memory monitor when it SIGKILLs the child for exceeding its RSS
    // budget, so that kill can be told apart from an external (OOM-killer) one.
    process: Option<(Child, JoinHandle<()>, Arc<AtomicBool>)>,
    output: Option<Result<Output, ExecutionError>>,

    global_clk: u64,
    clk: u64,
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

        Self { input, consumer, memory, process: None, output: None, global_clk: 0, clk: 0 }
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
            let (mut child, killed_by_monitor) = spawn_restricted(
                Command::new(crate::binary::get_binary_path()),
                self.input.memory_limit,
            )
            .map_err(|e| ExecutionError::Other(format!("failed to spawn child process: {e}")))?;

            // Start draining stderr before sending input. The input write is blocking, so a
            // child that fills its stderr pipe first would deadlock the exchange; draining
            // from the start also preserves its diagnostics if it dies before reading input.
            let stderr = child.stderr.take().expect("open stderr");
            let id = self.input.id.clone();
            let log_handle = thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for l in reader.lines().map_while(Result::ok) {
                    tracing::debug!("CHILD {}: {}", id, l);
                }
            });

            // Send the program input. If the child died during startup (e.g. OOM-killed) the
            // pipe breaks; surface its exit cause instead of panicking on the write.
            let send_result = {
                let stdin = child.stdin.take().expect("open stdin");
                let mut writer = BufWriter::new(stdin);
                match bincode::serialize_into(&mut writer, &self.input) {
                    Ok(()) => writer.flush().map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            };
            if let Err(send_err) = send_result {
                // The write almost always fails because the child already died. Kill defensively
                // in case it didn't, so the reap can't block; then collect its exit status and logs.
                let _ = child.kill();
                let status = child.wait().expect("wait for child to exit");
                let _ = log_handle.join();
                let error = if status.success() {
                    ExecutionError::Other(format!("failed sending input to child: {send_err}"))
                } else {
                    child_exit_error(&status, &killed_by_monitor)
                };
                self.output = Some(Err(error.clone()));
                return Err(error);
            }

            self.process = Some((child, log_handle, killed_by_monitor));
        }

        if let Some(consumer) = &self.consumer {
            // Looking for the next chunk
            loop {
                match consumer.access(Duration::from_millis(CONSUMER_TIMEOUT_MILLIS)) {
                    TraceResult::Data(guard) => {
                        let chunk = unsafe { TraceChunkRaw::from_shm(guard) };
                        self.global_clk = chunk.global_clk_end();
                        self.clk = chunk.clk_end();

                        return Ok(Some(chunk));
                    }
                    TraceResult::Finished => {
                        self.wait_for_success()?;
                        return Ok(None);
                    }
                    TraceResult::Crashed(details) => {
                        // Process logs, they might provide insight into why the program crashed.
                        let (_, log_thread, _) = self.process.take().unwrap();
                        log_thread.join().expect("wait for log thread to finish");
                        let opcode = match details.operation {
                            1 => Opcode::LD,
                            2 => Opcode::SD,
                            _ => Opcode::UNIMP,
                        };
                        let error = match details.signal {
                            libc::SIGSEGV => {
                                ExecutionError::InvalidMemoryAccess(opcode, details.addr)
                            }
                            // SIGILL: child hit a JIT `unimp` (see sp1-jit's unimp handler).
                            libc::SIGILL => ExecutionError::Unimplemented(),
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
                            if status.success() {
                                // The child terminates as normals, we need to process its output.
                                self.wait_for_success()?;
                                return Ok(None);
                            }
                            // The child terminates with some errors. We still want to process logs.
                            let (_, log_thread, killed_by_monitor) = self.process.take().unwrap();
                            log_thread.join().expect("wait for log thread to finish");
                            // Child process is terminated, let's find out why
                            if status.signal() == Some(libc::SIGBUS) {
                                tracing::warn!("SIGBUS signal is received, there is a chance /dev/shm is full!");
                            }
                            let error = child_exit_error(&status, &killed_by_monitor);
                            self.output = Some(Err(error.clone()));
                            return Err(error);
                        }
                        // Child process is still running, we spin and try again.
                        std::hint::spin_loop();
                    }
                }
            }
        } else {
            // Tracing mode is disabled, wait for process termination
            self.wait_for_success()?;
            Ok(None)
        }
    }

    fn wait_for_success(&mut self) -> Result<(), ExecutionError> {
        // SP1 program terminates, wait for output and terminate child process.
        let (mut child, log_thread, killed_by_monitor) = self.process.take().unwrap();
        let stdout = child.stdout.take().expect("open stdout");
        let mut stdout_reader = BufReader::new(stdout);

        // Read stdout before waiting to avoid a pipe-fill deadlock; a crashed child
        // closes the pipe (EOF) rather than blocking.
        let output: Result<Output, _> = bincode::deserialize_from(&mut stdout_reader);
        let status = child.wait().expect("wait for child to exit");
        log_thread.join().expect("wait for log thread to finish");

        match output {
            Ok(output) if status.success() => {
                self.global_clk = output.global_clk;
                self.clk = output.clk;
                self.output = Some(Ok(output));
                Ok(())
            }
            // Non-tracing runner has no crash handler, so map the exit signal to a
            // typed cause here instead of panicking (mirrors the Timeout branch).
            _ => {
                let error = child_exit_error(&status, &killed_by_monitor);
                self.output = Some(Err(error.clone()));
                Err(error)
            }
        }
    }

    fn output(&self) -> &Output {
        self.output
            .as_ref()
            .expect("Process is still running")
            .as_ref()
            .expect("Process terminated with error state")
    }

    fn take_output(self) -> Output {
        self.output
            .clone()
            .expect("Process is still running")
            .expect("Process terminated with error state")
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
        self.clk
    }

    /// Get the global clock of the JIT function.
    ///
    /// This clock is incremented by 1 per instruction.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        self.global_clk
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

    /// Get the public value digest words committed by the guest via `COMMIT` syscalls.
    #[must_use]
    pub fn public_value_digest(&self) -> [u32; sp1_jit::PUBLIC_VALUE_DIGEST_WORDS] {
        self.output().public_value_digest
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

    /// Get the page protection record for a specific page index.
    /// The native executor does not track page protection, so this always returns None.
    #[must_use]
    pub fn get_page_prot_record(&self, _page_idx: u64) -> Option<sp1_jit::PageProtValue> {
        None
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
        if let Some((mut child, _, _)) = self.process.take() {
            child.kill().expect("running child cannot be killed");
        }
        self.output = None;

        let (memory, consumer) = create(&self.input);
        self.memory = memory;
        self.consumer = consumer;

        self.global_clk = 0;
        self.clk = 0;
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

/// Maps a dead child's exit status to a typed [`ExecutionError`] instead of panicking.
///
/// A `SIGKILL` is split by `killed_by_monitor`: if our RSS monitor sent it, the program
/// exceeded its budget ([`ExecutionError::TooMuchMemory`]); otherwise it was an external
/// kill, e.g. the OS OOM-killer ([`ExecutionError::ChildKilled`]).
fn child_exit_error(
    status: &std::process::ExitStatus,
    killed_by_monitor: &AtomicBool,
) -> ExecutionError {
    match (status.code(), status.signal()) {
        (_, Some(libc::SIGKILL)) if killed_by_monitor.load(Ordering::SeqCst) => {
            ExecutionError::TooMuchMemory()
        }
        (_, Some(libc::SIGKILL)) => ExecutionError::ChildKilled(),
        (_, Some(libc::SIGILL)) => ExecutionError::Unimplemented(),
        (code, signal) => ExecutionError::Other(format!(
            "Child native executor terminated abnormally, code: {code:?}, signal: {signal:?}"
        )),
    }
}

/// Spawns a process with piped I/O and an RSS memory monitor thread.
fn spawn_restricted(
    mut cmd: Command,
    limit_bytes: u64,
) -> std::io::Result<(Child, Arc<AtomicBool>)> {
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    // Disable core dumps for the child by temporarily zeroing RLIMIT_CORE in the
    // parent (inherited via posix_spawn). Avoids pre_exec which forces fork().
    let child = unsafe {
        let mut old_limit: libc::rlimit = std::mem::zeroed();
        libc::getrlimit(libc::RLIMIT_CORE, &mut old_limit);

        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        let result = cmd.spawn();
        libc::setrlimit(libc::RLIMIT_CORE, &old_limit);

        result
    }?;
    let child_pid = child.id();

    let killed_by_monitor = Arc::new(AtomicBool::new(false));
    let monitor_flag = killed_by_monitor.clone();

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

                    // Flag before killing so the kill is attributable to us, not the OOM-killer.
                    monitor_flag.store(true, Ordering::SeqCst);
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
    Ok((child, killed_by_monitor))
}

impl Drop for MinimalExecutorRunner {
    fn drop(&mut self) {
        if let Some((mut child, _, _)) = self.process.take() {
            let _ = child.kill();
        }
    }
}

#[cfg(test)]
mod child_exit_error_tests {
    use super::child_exit_error;
    use sp1_core_executor::ExecutionError;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::atomic::AtomicBool;

    // A wait()-style status for a process killed by `signal` (low 7 bits on Unix).
    fn signaled(signal: i32) -> ExitStatus {
        ExitStatus::from_raw(signal)
    }

    #[test]
    fn sigkill_by_our_monitor_is_too_much_memory() {
        let flag = AtomicBool::new(true); // our RSS monitor sent the SIGKILL
        assert!(matches!(
            child_exit_error(&signaled(libc::SIGKILL), &flag),
            ExecutionError::TooMuchMemory()
        ));
    }

    #[test]
    fn external_sigkill_is_child_killed() {
        let flag = AtomicBool::new(false); // OOM-killer / external SIGKILL
        assert!(matches!(
            child_exit_error(&signaled(libc::SIGKILL), &flag),
            ExecutionError::ChildKilled()
        ));
    }

    #[test]
    fn sigill_is_unimplemented() {
        let flag = AtomicBool::new(false);
        assert!(matches!(
            child_exit_error(&signaled(libc::SIGILL), &flag),
            ExecutionError::Unimplemented()
        ));
    }
}
