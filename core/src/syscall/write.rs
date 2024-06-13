use crate::{
    runtime::{Register, Syscall, SyscallContext},
    utils::num_to_comma_separated,
};

pub struct SyscallWrite;

impl SyscallWrite {
    pub const fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallWrite {
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
            if s.contains("cycle-tracker-start:") {
                let fn_name = s
                    .split("cycle-tracker-start:")
                    .last()
                    .unwrap()
                    .trim_end()
                    .trim_start();
                let depth = rt.cycle_tracker.len() as u32;
                rt.cycle_tracker
                    .insert(fn_name.to_string(), (rt.state.global_clk, depth));
                let padding = (0..depth).map(|_| "│ ").collect::<String>();
                log::debug!("{}┌╴{}", padding, fn_name);
            } else if s.contains("cycle-tracker-end:") {
                let fn_name = s
                    .split("cycle-tracker-end:")
                    .last()
                    .unwrap()
                    .trim_end()
                    .trim_start();
                let (start, depth) = rt.cycle_tracker.remove(fn_name).unwrap_or((0, 0));
                // Leftpad by 2 spaces for each depth.
                let padding = (0..depth).map(|_| "│ ").collect::<String>();
                log::info!(
                    "{}└╴{} cycles",
                    padding,
                    num_to_comma_separated(rt.state.global_clk - start as u64)
                );
            } else {
                let flush_s = update_io_buf(ctx, fd, s);
                if !flush_s.is_empty() {
                    flush_s
                        .into_iter()
                        .for_each(|line| println!("stdout: {}", line));
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
        } else if let Some(hook) = rt.hook_registry.table.get(&fd) {
            rt.state.input_stream.extend(hook(rt.hook_env(), slice));
        } else {
            log::warn!("tried to write to unknown file descriptor {fd}");
        }
        None
    }
}

pub fn update_io_buf(ctx: &mut SyscallContext, fd: u32, s: &str) -> Vec<String> {
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
