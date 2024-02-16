use crate::{
    runtime::{Register, Syscall, SyscallContext},
    utils::u32_to_comma_separated,
};

pub struct SyscallWrite;

impl SyscallWrite {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallWrite {
    fn execute(&self, ctx: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let a0 = Register::X10;
        let a1 = Register::X11;
        let a2 = Register::X12;
        let rt = &mut ctx.rt;
        let fd = rt.register(a0);
        if fd == 1 || fd == 2 || fd == 3 || fd == 4 {
            let write_buf = rt.register(a1);
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
                    log::info!("{}┌╴{}", padding, fn_name);
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
                        u32_to_comma_separated(rt.state.global_clk - start)
                    );
                } else {
                    log::info!("stdout: {}", s.trim_end());
                }
            } else if fd == 2 {
                let s = core::str::from_utf8(slice).unwrap();
                log::info!("stderr: {}", s.trim_end());
            } else if fd == 3 {
                rt.state.output_stream.extend_from_slice(slice);
            } else if fd == 4 {
                rt.state.input_stream.extend_from_slice(slice);
            } else {
                unreachable!()
            }
        }
        Some(0)
    }
}
