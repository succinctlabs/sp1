use std::io::Write;

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

        // If RUST_LOG is set to "trace", then log the current state of the runtime every cycle.
        let width = 12;
        let registers = self.registers();
        log::trace!(
            "clk={} [pc=0x{:x?}] {:<width$?} |         x0={:<width$} x1={:<width$} x2={:<width$} x3={:<width$} x4={:<width$} x5={:<width$} x6={:<width$} x7={:<width$} x8={:<width$} x9={:<width$} x10={:<width$} x11={:<width$} x12={:<width$} x13={:<width$} x14={:<width$} x15={:<width$} x16={:<width$} x17={:<width$} x18={:<width$}",
            self.state.global_clk,
            self.state.pc,
            instruction,
            registers[0],
            registers[1],
            registers[2],
            registers[3],
            registers[4],
            registers[5],
            registers[6],
            registers[7],
            registers[8],
            registers[9],
            registers[10],
            registers[11],
            registers[12],
            registers[13],
            registers[14],
            registers[15],
            registers[16],
            registers[17],
            registers[18],
        );

        if !self.unconstrained && self.state.global_clk % 10_000_000 == 0 {
            log::info!(
                "clk = {} pc = 0x{:x?}",
                self.state.global_clk,
                self.state.pc
            );
        }
    }
}
