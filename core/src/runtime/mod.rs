//! Runtime
//!
//! The runtime module is responsible for managing the execution of the program and the production
//! of the program execution trace. As the virtual machine arithmetization is bounded, the runtime
//! runs the program for a particular number of cycles at a time, and then returns the execution
//! trace of each cycle segment.

mod store;
mod writer;

use anyhow::Result;

use crate::program::ISA;

pub use store::FunctionStore;
pub use store::Store;

use self::writer::PollResult;
use self::writer::TraceWrite;

pub mod base;

/// A runtime instance.
///
/// A runtime instance is a collection of modules that have been instantiated together with a store
/// external host functions, and any other instance necessary to run the program.
pub trait Runtime<IS: ISA, S: Store>: Send + Sync {
    /// Execute an instruction and return the new state to be recorded.
    fn execute(&self, instruction: &IS::Instruction, store: &mut S) -> Result<S::Event>;

    /// Get the next instruction to be executed.
    fn get_next_instruction(&self, store: &mut S) -> Option<IS::Instruction>;

    /// Run the instance.
    ///
    /// The runtime will run the program by executing the instruction in sequence and will stream
    /// the execution trace to the writer. The runtime will stop when the program has finished or
    /// when the writer returns a `halt` signal.
    fn run(&self, store: &mut S, writer: &mut impl TraceWrite) -> Result<()> {
        while let Some(instruction) = self.get_next_instruction(store) {
            let state = self.execute(&instruction, store).unwrap();
            let bytes = bincode::serialize(&state)?;
            writer.write_all(&bytes)?;
            match writer.poll()? {
                PollResult::Halt => break,
                PollResult::Continue => (),
            }
        }
        Ok(())
    }
}
