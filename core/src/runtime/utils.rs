use std::io::Write;

use crate::runtime::ExecutionReport;

use super::{Instruction, Runtime};

pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

macro_rules! assert_valid_memory_access {
    ($addr:expr, $position:expr) => {
        #[cfg(debug_assertions)]
        {
            use p3_baby_bear::BabyBear;
            use p3_field::AbstractField;
            match $position {
                MemoryAccessPosition::Memory => {
                    assert_eq!($addr % 4, 0, "addr is not aligned");
                    BabyBear::from_canonical_u32($addr);
                    assert!($addr > 40);
                }
                _ => {
                    Register::from_u32($addr);
                }
            };
        }

        #[cfg(not(debug_assertions))]
        {}
    };
}

impl<'a> Runtime<'a> {
    #[inline]
    pub fn log(&mut self, instruction: &Instruction) {
        // Write the current program counter to the trace buffer for the cycle tracer.
        if let Some(ref mut buf) = self.trace_buf {
            if !self.unconstrained {
                buf.write_all(&u32::to_be_bytes(self.state.pc)).unwrap();
            }
        }

        if !self.unconstrained && self.state.global_clk % 10_000_000 == 0 {
            log::info!(
                "clk = {} pc = 0x{:x?}",
                self.state.global_clk,
                self.state.pc
            );
            println!("{}", self.report_single);
            self.report_single = ExecutionReport::default();
        }
    }
}
