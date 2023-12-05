pub mod air;
pub mod alu;
pub mod cpu;
pub mod program;
pub mod runtime;
pub mod segment;

pub struct Word<F>([F; 4]);
