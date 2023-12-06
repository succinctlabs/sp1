mod event;
mod function;

pub use event::Event;
pub use function::FunctionStore;

/// A store represents all global state that can be accessed by a program.
///
/// A minimal store must include a memory. A more complete store may also include some other forms
/// of internal state such as inputs, outputs, registers, etc.
pub trait Store {
    /// The snapshot of the state that is recorded in the execution trace.
    type Event: Event;
    /// Get a mutable reference to the memory of the store.
    fn memory(&mut self) -> &mut [u8];

    /// Get a mutable reference to the program counter.
    fn pc(&mut self) -> &mut u32;

    /// Get a mutable reference to the frame pointer.
    fn fp(&mut self) -> &mut u32;

    /// Get a mutable reference to the clock.
    fn clk(&mut self) -> &mut u32;
}
