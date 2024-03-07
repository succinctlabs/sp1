use crate::asm::Instruction;

pub trait Builder {
    /// Get stack memory.
    fn get_mem(&mut self, size: usize) -> u32;
    //  Allocate heap memory.
    // fn alloc(&mut self, size: Int) -> Int;

    fn push(&mut self, instruction: Instruction);
}

pub trait Add<B> {
    fn add(self, other: Self, builder: &mut B) -> Self;
}

pub trait Mul<B> {
    fn mul(self, other: Self, builder: &mut B) -> Self;
}

pub trait Sub<B> {
    fn sub(self, other: Self, builder: &mut B) -> Self;
}

pub trait Div<B> {
    fn div(self, other: Self, builder: &mut B) -> Self;
}
