use std::collections::HashMap;

use crate::asm::Instruction;
use crate::ir::Address;
use crate::ir::Variable;

pub struct Module {
    functions: HashMap<String, AsmFunction>,
}

pub trait Builder: Sized {
    /// An allocation of aligned memory with `size`.
    fn malloc(&mut self, size: usize) -> Address;

    fn init<T: Variable>(&mut self) -> T {
        T::from_address(self.malloc(T::size_of()))
    }

    fn call(&mut self, function: AsmFunction);
}

pub struct AsmFunction {
    ident: String,
    code_blocks: HashMap<String, Vec<Instruction>>,
}

pub struct FunctionBuilder {
    mp: usize,
    heap_ptr: usize,
    code_blocks: Vec<(String, Vec<Instruction>)>,
}

pub struct AsmBuilder {
    mp: usize,

    heap_ptr: usize,

    current_block: Vec<Instruction>,

    functions: HashMap<String, AsmFunction>,
}

impl Builder for AsmBuilder {
    fn malloc(&mut self, size: usize) -> Address {
        let reminder = self.ap % size;
        if reminder != 0 {
            self.ap += size - reminder;
        }
        let ap = self.ap;
        self.ap += size;
        Address::Main(ap as u32)
    }

    fn call<F: Function<Self>>(&mut self, function: F) {
        if !self.functions.contains_key(&function.ident()) {
            let current_block = self.current_block.clone();

            self.current_block.clear();
        }
    }
}
