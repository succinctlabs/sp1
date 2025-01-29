use sp1_primitives::consts::fd::{FD_HINT, FD_PUBLIC_VALUES, LOWEST_ALLOWED_FD};
use sp1_primitives::consts::num_to_comma_separated;

use crate::{Executor, Register};

use super::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct WriteSyscall;

impl Syscall for WriteSyscall {
    /// Handle writes to file descriptors during execution.
    ///
    /// If stdout (fd = 1):
    /// - If the stream is a cycle tracker, either log the cycle tracker or accumulate it in the
    ///   report.
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
    #[allow(clippy::pedantic)]
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let a2 = Register::X12;
        let rt = &mut ctx.rt;
        let fd = arg1;
        let write_buf = arg2;
        let nbytes = rt.register(a2);
        // Read nbytes from memory starting at write_buf.
        let bytes = (0..nbytes).map(|i| rt.byte(write_buf + i)).collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        if fd == 1 {
            let s = core::str::from_utf8(slice).unwrap();
            match parse_cycle_tracker_command(s) {
                Some(command) => handle_cycle_tracker_command(rt, command),
                None => {
                    // If the string does not match any known command, print it to stdout.
                    let flush_s = update_io_buf(ctx, fd, s);
                    if !flush_s.is_empty() {
                        flush_s.into_iter().for_each(|line| eprintln!("stdout: {}", line));
                    }
                }
            }
        } else if fd == 2 {
            let s = core::str::from_utf8(slice).unwrap();
            let flush_s = update_io_buf(ctx, fd, s);
            if !flush_s.is_empty() {
                flush_s.into_iter().for_each(|line| eprintln!("stderr: {}", line));
            }
        } else if fd <= LOWEST_ALLOWED_FD {
            if std::env::var("SP1_ALLOW_DEPRECATED_HOOKS")
                .map(|r| {
                    r.parse::<bool>().expect("failed to parse SP1_ALLOW_DEPRECATED_HOOKS as bool")
                })
                .unwrap_or(false)
            {
                const PUBLIC_VALUES: u32 = 3;
                const INPUT: u32 = 4;
                const ECRECOVER_V1: u32 = 5;
                const ECRECOVER_R1: u32 = 6;
                const ECRECOVER_V2: u32 = 7;
                const ED_DECOMPRESS: u32 = 8;

                let res = if fd == ECRECOVER_V1 {
                    crate::hook::deprecated_hooks::hook_ecrecover(rt.hook_env(), slice)
                } else if fd == ECRECOVER_R1 {
                    crate::hook::deprecated_hooks::hook_r1_ecrecover(rt.hook_env(), slice)
                } else if fd == ECRECOVER_V2 {
                    crate::hook::deprecated_hooks::hook_ecrecover_v2(rt.hook_env(), slice)
                } else if fd == ED_DECOMPRESS {
                    crate::hook::deprecated_hooks::hook_ed_decompress(rt.hook_env(), slice)
                } else if fd == PUBLIC_VALUES {
                    rt.state.public_values_stream.extend_from_slice(slice);
                    vec![]
                } else if fd == INPUT {
                    rt.state.input_stream.push_front(slice.to_vec());
                    vec![]
                } else {
                    vec![]
                };

                if !res.is_empty() {
                    for val in res.into_iter().rev() {
                        rt.state.input_stream.push_front(val);
                    }
                }
            } else {
                panic!(
                    "You are using reserved file descriptor {fd} that is not supported on SP1 versions >= v4.0.0. \
                    Update your patches to the latest versions that are compatible with versions >= v4.0.0. \
                    See `https://docs.succinct.xyz/docs/writing-programs/patched-crates` for more information"
                );
            }
        } else if fd == FD_PUBLIC_VALUES {
            rt.state.public_values_stream.extend_from_slice(slice);
        } else if fd == FD_HINT {
            rt.state.input_stream.push_front(slice.to_vec());
        } else if let Some(mut hook) = rt.hook_registry.get(fd) {
            let res = hook.invoke_hook(rt.hook_env(), slice);

            // Write the result back to the input stream.
            //
            // Note: The result is written in reverse order to the input stream to maintain the
            // order.
            for val in res.into_iter().rev() {
                rt.state.input_stream.push_front(val);
            }
        } else {
            tracing::warn!("tried to write to unknown file descriptor {fd}");
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

/// Parse a cycle tracker command from a string. If the string does not match any known command,
/// returns None.
fn parse_cycle_tracker_command(s: &str) -> Option<CycleTrackerCommand> {
    let (command, fn_name) = s.split_once(':')?;
    let trimmed_name = fn_name.trim().to_string();

    match command {
        "cycle-tracker-start" => Some(CycleTrackerCommand::Start(trimmed_name)),
        "cycle-tracker-end" => Some(CycleTrackerCommand::End(trimmed_name)),
        "cycle-tracker-report-start" => Some(CycleTrackerCommand::ReportStart(trimmed_name)),
        "cycle-tracker-report-end" => Some(CycleTrackerCommand::ReportEnd(trimmed_name)),
        _ => None,
    }
}

/// Handle a cycle tracker command.
fn handle_cycle_tracker_command(rt: &mut Executor, command: CycleTrackerCommand) {
    match command {
        CycleTrackerCommand::Start(name) | CycleTrackerCommand::ReportStart(name) => {
            start_cycle_tracker(rt, &name);
        }
        CycleTrackerCommand::End(name) => {
            end_cycle_tracker(rt, &name);
        }
        CycleTrackerCommand::ReportEnd(name) => {
            // Attempt to end the cycle tracker and accumulate the total cycles in the fn_name's
            // entry in the ExecutionReport.
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
fn start_cycle_tracker(rt: &mut Executor, name: &str) {
    let depth = rt.cycle_tracker.len() as u32;
    rt.cycle_tracker.insert(name.to_string(), (rt.state.global_clk, depth));
    let padding = "│ ".repeat(depth as usize);
    tracing::info!("{}┌╴{}", padding, name);
}

/// End tracking cycles for the given name, print out the log, and return the total number of cycles
/// in the span. If the name is not found in the cycle tracker cache, returns None.
fn end_cycle_tracker(rt: &mut Executor, name: &str) -> Option<u64> {
    if let Some((start, depth)) = rt.cycle_tracker.remove(name) {
        let padding = "│ ".repeat(depth as usize);
        let total_cycles = rt.state.global_clk - start;
        tracing::info!("{}└╴{} cycles", padding, num_to_comma_separated(total_cycles));
        return Some(total_cycles);
    }
    None
}

/// Update the io buffer for the given file descriptor with the given string.
#[allow(clippy::mut_mut)]
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
        lines.into_iter().map(std::string::ToString::to_string).collect::<Vec<String>>()
    } else {
        vec![]
    }
}
