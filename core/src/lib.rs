pub mod air;
pub mod alu;
pub mod cpu;
pub mod program;
pub mod runtime;

pub const WORD_SIZE: usize = 4;
pub struct Word<F>([F; WORD_SIZE]);
