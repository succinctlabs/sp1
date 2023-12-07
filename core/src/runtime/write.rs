use anyhow::Result;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PollResult {
    Halt,
    Continue,
}

pub trait TraceWrite: Write {
    /// Poll the writer to see if we should continue execution.
    fn poll(&mut self) -> Result<PollResult>;
}
