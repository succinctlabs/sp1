mod merkle;
mod util;

use std::collections::BTreeMap;

use crate::{
    memory::{state::util::page_id, MemOp},
    runtime::Runtime,
};

use super::{
    page::{InputPage, OutputPage},
    MemoryEvent,
};

pub struct MemoryState {
    pub input_pages: Vec<InputPage>,
    pub output_pages: Vec<OutputPage>,

    initial_state: BTreeMap<u32, u32>,

    in_events: Vec<MemoryEvent>,
    out_events: Vec<MemoryEvent>,
}

impl MemoryState {
    pub fn new(memory_state: BTreeMap<u32, u32>) -> Self {
        Self {
            input_pages: Vec::new(),
            output_pages: Vec::new(),
            initial_state: memory_state,
            in_events: Vec::new(),
            out_events: Vec::new(),
        }
    }

    pub fn update(&mut self, runtime: &mut Runtime) {
        let mut events = runtime.memory_events.clone();
        // Sort the events by address and then by clock cycle.
        events.sort_by_key(|event| (event.addr, event.clk, event.op));

        // For each address, do the following:
        // 1. If the first event is a read:
        //    + add a a write of it with `clk = 0` from the initial memory state.
        //    + register the read event to the `in_events` vector.
        //    + Add the corresponding pade id to `input_pages`.
        // 2. If the address has at least one write event:
        //    + register the last event of the address to the `out_events` vector.
        //    + Add the corresponding pade id to `output_pages`.
        let mut last_address = None;
        let mut last_event = None;
        let mut was_written = false;
        for event in events {
            let current_address = event.addr;

            if let Some(addr) = last_address {
                if addr != current_address {
                    if was_written {
                        self.out_events.push(last_event.unwrap());
                        self.output_pages.push(OutputPage::new(page_id(addr)));
                    }
                    if event.op == MemOp::Read {
                        self.in_events.push(event);
                        self.input_pages.push(InputPage::new(page_id(addr)));
                        runtime.memory_events.push(MemoryEvent {
                            addr,
                            value: self.initial_state.get(&addr).copied().unwrap_or(0),
                            clk: 0,
                            op: MemOp::Write,
                        });
                    }
                    was_written = event.op == MemOp::Write;
                } else {
                    was_written |= event.op == MemOp::Write;
                }
            } else {
                if event.op == MemOp::Read {
                    self.in_events.push(event);
                    self.input_pages
                        .push(InputPage::new(page_id(current_address)));
                    runtime.memory_events.push(MemoryEvent {
                        addr: current_address,
                        value: self
                            .initial_state
                            .get(&current_address)
                            .copied()
                            .unwrap_or(0),
                        clk: 0,
                        op: MemOp::Write,
                    });
                } else {
                    was_written = true;
                }
            }
            last_address = Some(current_address);
            last_event = Some(event);
        }
    }
}
