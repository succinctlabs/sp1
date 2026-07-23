use sp1_jit::{RiscRegister, SyscallContext};
use sp1_primitives::consts::fd::{
    FD_BLS12_381_INVERSE, FD_BLS12_381_SQRT, FD_ECRECOVER_HOOK, FD_EDDECOMPRESS, FD_FP_INV,
    FD_FP_SQRT, FD_HINT, FD_PUBLIC_VALUES, FD_RSA_MUL_MOD,
};

#[cfg(feature = "profiling")]
mod cycle_tracker {
    /// Format a number with comma separators (e.g., 1234567 -> "1,234,567").
    pub fn format_with_commas(n: u64) -> String {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    }

    /// Parse a cycle tracker command from a line.
    /// Returns `Some((command_type, name))` if the line is a cycle tracker command.
    pub fn parse_command(line: &str) -> Option<(&'static str, &str)> {
        if let Some(name) = line.strip_prefix("cycle-tracker-report-start:") {
            Some(("report-start", name.trim()))
        } else if let Some(name) = line.strip_prefix("cycle-tracker-report-end:") {
            Some(("report-end", name.trim()))
        } else if let Some(name) = line.strip_prefix("cycle-tracker-start:") {
            Some(("start", name.trim()))
        } else if let Some(name) = line.strip_prefix("cycle-tracker-end:") {
            Some(("end", name.trim()))
        } else {
            None
        }
    }
}

#[cfg(feature = "profiling")]
fn handle_output(ctx: &mut impl SyscallContext, fd: u64, content: &str) {
    use cycle_tracker::{format_with_commas, parse_command};

    if fd == 1 {
        // stdout - process cycle tracker commands
        for line in content.lines() {
            if let Some((cmd, name)) = parse_command(line) {
                match cmd {
                    "start" | "report-start" => {
                        let depth = ctx.cycle_tracker_start(name);
                        let padding = "│ ".repeat(depth as usize);
                        tracing::info!("{}┌╴{}", padding, name);
                    }
                    "end" => {
                        if let Some((cycles, depth)) = ctx.cycle_tracker_end(name) {
                            let padding = "│ ".repeat(depth as usize);
                            tracing::info!("{}└╴{} cycles", padding, format_with_commas(cycles));
                        } else {
                            tracing::info!("└╴{} (no matching start)", name);
                        }
                    }
                    "report-end" => {
                        if let Some((cycles, depth)) = ctx.cycle_tracker_report_end(name) {
                            let padding = "│ ".repeat(depth as usize);
                            tracing::info!("{}└╴{} cycles", padding, format_with_commas(cycles));
                        } else {
                            tracing::info!("└╴{} (no matching start)", name);
                        }
                    }
                    _ => {}
                }
            } else {
                // Non-cycle-tracker output - print as before
                eprintln!("stdout: {line}");
            }
        }
    } else {
        // stderr - just print
        for line in content.lines() {
            eprintln!("stderr: {line}");
        }
    }
}

#[cfg(not(feature = "profiling"))]
fn handle_output(_ctx: &mut impl SyscallContext, fd: u64, content: &str) {
    let prefix = if fd == 1 { "stdout" } else { "stderr" };
    for line in content.lines() {
        eprintln!("{prefix}: {line}");
    }
}

pub(crate) unsafe fn write(ctx: &mut impl SyscallContext, arg1: u64, arg2: u64) -> Option<u64> {
    let a2 = RiscRegister::X12;
    let fd = arg1;
    let buf_ptr = arg2;

    let nbytes = ctx.rr(a2);
    // Round down to low word start.
    let start = buf_ptr & !7;
    // Get the intra-word offset of the start.
    let head = (buf_ptr & 7) as usize;
    // Include the head bytes so we get the correct number of words.
    let nwords = (head + nbytes as usize).div_ceil(8);

    let slice = ctx.mr_slice_no_trace(start, nwords);
    let bytes = slice
        .into_iter()
        .copied()
        .flat_map(u64::to_le_bytes)
        .skip(head)
        .take(nbytes as usize)
        .collect::<Vec<u8>>();

    let slice = bytes.as_slice();
    if fd == 1 || fd == 2 {
        // Capture a bounded stderr tail (panic message + location) for debugging; stdout is
        // not captured. The existing host-stderr printing below is preserved.
        if fd == 2 {
            ctx.record_stderr(slice);
        }
        handle_output(ctx, fd, &String::from_utf8_lossy(slice));
        return None;
    } else if fd as u32 == FD_PUBLIC_VALUES {
        ctx.public_values_stream().extend_from_slice(slice);
        return None;
    } else if fd as u32 == FD_HINT {
        ctx.input_buffer().push_front(bytes);
        return None;
    }

    use crate::hook::{bls, fp_ops, hook_ecrecover, hook_ed_decompress, hook_rsa_mul_mod, HookEnv};
    let env = HookEnv {};
    let hook_return = match fd as u32 {
        FD_BLS12_381_INVERSE => Some(bls::hook_bls12_381_inverse(env, slice)),
        FD_BLS12_381_SQRT => Some(bls::hook_bls12_381_sqrt(env, slice)),
        FD_FP_INV => Some(fp_ops::hook_fp_inverse(env, slice)),
        FD_FP_SQRT => Some(fp_ops::hook_fp_sqrt(env, slice)),
        FD_ECRECOVER_HOOK => Some(hook_ecrecover(env, slice)),
        FD_EDDECOMPRESS => Some(hook_ed_decompress(env, slice)),
        FD_RSA_MUL_MOD => Some(hook_rsa_mul_mod(env, slice)),
        _ => {
            tracing::warn!("Unsupported file descriptor: {}", fd);
            None
        }
    };

    if let Some(hook_return) = hook_return {
        for item in hook_return.into_iter().rev() {
            ctx.input_buffer().push_front(item);
        }
    }

    None
}
