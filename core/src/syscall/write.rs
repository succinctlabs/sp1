use crate::{
    runtime::{Register, Runtime, Syscall, SyscallContext},
    utils::num_to_comma_separated,
};

pub struct SyscallWrite;

impl SyscallWrite {
    pub const fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallWrite {
    /// Handle writes to file descriptors during execution.
    ///
    /// If stdout (fd = 1):
    /// - If the stream is a cycle tracker, either log the cycle tracker or accumulate it in the report.
    /// - Else, print the stream to stdout.
    ///
    /// If stderr (fd = 2):
    /// - Print the stream to stderr.
    ///
    /// If fd = 3:
    /// - Update the public value stream.
    ///
    /// If fd = 4:
    /// - Update the input stream.
    ///
    /// If the fd matches a hook in the hook registry, invoke the hook.
    ///
    /// Else, log a warning.
    fn execute(&self, ctx: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let a2 = Register::X12;
        let rt = &mut ctx.rt;
        let fd = arg1;
        let write_buf = arg2;
        let nbytes = rt.register(a2);
        // Read nbytes from memory starting at write_buf.
        let bytes = (0..nbytes)
            .map(|i| rt.byte(write_buf + i))
            .collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        if fd == 1 {
            let s = core::str::from_utf8(slice).unwrap();
            match parse_cycle_tracker_command(s) {
                Some(command) => handle_cycle_tracker_command(rt, command),
                None => {
                    let flush_s = update_io_buf(ctx, fd, s);
                    if !flush_s.is_empty() {
                        flush_s
                            .into_iter()
                            .for_each(|line| println!("stdout: {}", line));
                    }
                }
            }
        } else if fd == 2 {
            let s = core::str::from_utf8(slice).unwrap();
            let flush_s = update_io_buf(ctx, fd, s);
            if !flush_s.is_empty() {
                flush_s
                    .into_iter()
                    .for_each(|line| println!("stderr: {}", line));
            }
        } else if fd == 3 {
            rt.state.public_values_stream.extend_from_slice(slice);
        } else if fd == 4 {
            rt.state.input_stream.push(slice.to_vec());
        } else if let Some(mut hook) = rt.hook_registry.get(&fd) {
            let res = hook.invoke_hook(rt.hook_env(), slice);
            // Add result vectors to the beginning of the stream.
            let ptr = rt.state.input_stream_ptr;
            rt.state.input_stream.splice(ptr..ptr, res);
        } else {
            log::warn!("tried to write to unknown file descriptor {fd}");
        }
        None
    }
}

/// An enum representing the different cycle tracker commands.
#[derive(Clone)]
enum CycleTrackerCommand {
    Start(String),
    End(String),
    ReportStart(String),
    ReportEnd(String),
}

fn parse_cycle_tracker_command(s: &str) -> Option<CycleTrackerCommand> {
    match s.split_once(':') {
        Some(("cycle-tracker-start", name)) => {
            Some(CycleTrackerCommand::Start(name.trim().to_string()))
        }
        Some(("cycle-tracker-end", name)) => {
            Some(CycleTrackerCommand::End(name.trim().to_string()))
        }
        Some(("cycle-tracker-report-start", name)) => {
            Some(CycleTrackerCommand::ReportStart(name.trim().to_string()))
        }
        Some(("cycle-tracker-report-end", name)) => {
            Some(CycleTrackerCommand::ReportEnd(name.trim().to_string()))
        }
        _ => None,
    }
}

fn handle_cycle_tracker_command(rt: &mut Runtime, command: CycleTrackerCommand) {
    match command {
        CycleTrackerCommand::Start(name) | CycleTrackerCommand::ReportStart(name) => {
            start_cycle_tracker(rt, &name)
        }
        CycleTrackerCommand::End(name) => {
            end_cycle_tracker(rt, &name);
        }
        CycleTrackerCommand::ReportEnd(name) => {
            if let Some(total_cycles) = end_cycle_tracker(rt, &name) {
                rt.report
                    .cycle_tracker
                    .entry(name.to_string())
                    .and_modify(|cycles| *cycles += total_cycles)
                    .or_insert(total_cycles);
            }
        }
    }
}

/// Start tracking cycles for the given name at the specific depth and print out the log.
fn start_cycle_tracker(rt: &mut Runtime, name: &str) {
    let depth = rt.cycle_tracker.len() as u32;
    rt.cycle_tracker
        .insert(name.to_string(), (rt.state.global_clk, depth));
    let padding = "│ ".repeat(depth as usize);
    log::info!("{}┌╴{}", padding, name);
}

/// End tracking cycles for the given name, print out the log, and return the total number of cycles in the span.
/// If the name is not found in the cycle tracker cache, returns None.
fn end_cycle_tracker(rt: &mut Runtime, name: &str) -> Option<u64> {
    if let Some((start, depth)) = rt.cycle_tracker.remove(name) {
        let padding = "│ ".repeat(depth as usize);
        let total_cycles = rt.state.global_clk - start as u64;
        log::info!(
            "{}└╴{} cycles",
            padding,
            num_to_comma_separated(total_cycles)
        );
        return Some(total_cycles);
    }
    None
}

fn update_io_buf(ctx: &mut SyscallContext, fd: u32, s: &str) -> Vec<String> {
    let rt = &mut ctx.rt;
    let entry = rt.io_buf.entry(fd).or_default();
    entry.push_str(s);
    if entry.contains('\n') {
        // Return lines except for the last from buf.
        let prev_buf = std::mem::take(entry);
        let mut lines = prev_buf.split('\n').collect::<Vec<&str>>();
        let last = lines.pop().unwrap_or("");
        *entry = last.to_string();
        lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<String>>()
    } else {
        vec![]
    }
}
