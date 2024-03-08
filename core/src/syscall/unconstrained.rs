use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::runtime::{DummyEventReceiver, EventReceiver, ForkState, Syscall, SyscallContext};

pub struct SyscallEnterUnconstrained;

impl SyscallEnterUnconstrained {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallEnterUnconstrained {
    fn execute(&self, ctx: &mut SyscallContext) -> u32 {
        if ctx.rt.unconstrained {
            panic!("Unconstrained block is already active.");
        }
        ctx.rt.unconstrained = true;
        let mut receiver: Rc<RefCell<dyn EventReceiver>> =
            Rc::new(RefCell::new(DummyEventReceiver {}));
        std::mem::swap(&mut ctx.rt.event_receiver, &mut receiver);
        ctx.rt.unconstrained_state = ForkState {
            global_clk: ctx.rt.state.global_clk,
            clk: ctx.rt.state.clk,
            pc: ctx.rt.state.pc,
            memory_diff: HashMap::default(),
            event_receiver: receiver,
            op_record: std::mem::take(&mut ctx.rt.cpu_record),
        };
        1
    }
}

pub struct SyscallExitUnconstrained;

impl SyscallExitUnconstrained {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallExitUnconstrained {
    fn execute(&self, ctx: &mut SyscallContext) -> u32 {
        // Reset the state of the runtime.
        if ctx.rt.unconstrained {
            ctx.rt.state.global_clk = ctx.rt.unconstrained_state.global_clk;
            ctx.rt.state.clk = ctx.rt.unconstrained_state.clk;
            ctx.rt.state.pc = ctx.rt.unconstrained_state.pc;
            ctx.next_pc = ctx.rt.state.pc.wrapping_add(4);
            for (addr, value) in ctx.rt.unconstrained_state.memory_diff.drain() {
                match value {
                    Some(value) => {
                        ctx.rt.state.memory.insert(addr, value);
                    }
                    None => {
                        ctx.rt.state.memory.remove(addr);
                    }
                }
            }
            // ctx.rt.event_receiver = std::mem::take(&mut ctx.rt.unconstrained_state.event_receiver);
            std::mem::swap(
                &mut ctx.rt.event_receiver,
                &mut ctx.rt.unconstrained_state.event_receiver,
            );
            ctx.rt.cpu_record = std::mem::take(&mut ctx.rt.unconstrained_state.op_record);
            ctx.rt.unconstrained = false;
        }
        ctx.rt.unconstrained_state = ForkState::default();
        0
    }
}
