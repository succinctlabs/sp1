use crate::asm::AsmInstruction;
use crate::ir::Constant;
use crate::ir::Variable;

use crate::ir::Expression;
use crate::ir::Felt;
use crate::prelude::Symbolic;

use p3_field::AbstractField;
use p3_field::PrimeField32;

pub trait Builder: Sized {
    type F: PrimeField32;
    /// Get stack memory.
    fn get_mem(&mut self, size: usize) -> i32;
    //  Allocate heap memory.
    // fn alloc(&mut self, size: Int) -> Int;

    fn push(&mut self, instruction: AsmInstruction<Self::F>);

    // fn push_to_block(&mut self, block_label: Self::F, instruction: AsmInstruction<Self::F>);

    fn basic_block(&mut self);

    fn block_label(&mut self) -> Self::F;

    fn next_label(&mut self) -> Self::F;

    fn set_current_block(&mut self, label: Self::F);

    fn uninit<T: Variable<Self>>(&mut self) -> T {
        T::uninit(self)
    }

    fn constant<T: Constant<Self>>(&mut self, value: T::Constant) -> T {
        let var = T::uninit(self);
        var.imm(value, self);
        var
    }

    fn assign<E: Expression<Self>>(&mut self, dst: E::Value, expr: E) {
        expr.assign(dst, self);
    }

    fn eval<E: Expression<Self>>(&mut self, expr: E) -> E::Value {
        let dst = E::Value::uninit(self);
        expr.assign(dst, self);
        dst
    }

    /// Create a `ForBuilder` for a range of values.
    ///
    /// *Warning*: Starting with end < start will lead to undefined behavior!
    fn range(&mut self, start: Felt<Self::F>, end: Felt<Self::F>) -> ForBuilder<Self> {
        let loop_var = Felt::uninit(self);
        ForBuilder {
            builder: self,
            start,
            end,
            loop_var,
        }
    }

    fn if_eq<E1, E2>(&mut self, rhs: E1, lhs: E2) -> CondBuilder<Self>
    where
        E1: Into<Symbolic<Self::F>>,
        E2: Into<Symbolic<Self::F>>,
    {
        let lhs = lhs.into();
        let rhs = rhs.into();
        CondBuilder {
            builder: self,
            lhs,
            rhs,
            eq: true,
            then_label: None,
            else_label: None,
        }
    }

    fn if_neq<E1, E2>(&mut self, rhs: E1, lhs: E2) -> CondBuilder<Self>
    where
        E1: Into<Symbolic<Self::F>>,
        E2: Into<Symbolic<Self::F>>,
    {
        let lhs = lhs.into();
        let rhs = rhs.into();
        CondBuilder {
            builder: self,
            lhs,
            rhs,
            eq: false,
            then_label: None,
            else_label: None,
        }
    }
}

/// A builder for a conditional statement.
pub struct CondBuilder<'a, B: Builder> {
    builder: &'a mut B,
    lhs: Symbolic<B::F>,
    rhs: Symbolic<B::F>,
    eq: bool,
    then_label: Option<B::F>,
    else_label: Option<B::F>,
}

impl<'a, B: Builder> Builder for CondBuilder<'a, B> {
    type F = B::F;
    fn get_mem(&mut self, size: usize) -> i32 {
        self.builder.get_mem(size)
    }

    fn push(&mut self, instruction: AsmInstruction<B::F>) {
        self.builder.push(instruction);
    }

    // fn push_to_block(&mut self, block_label: Self::F, instruction: AsmInstruction<Self::F>) {
    //     self.builder.push_to_block(block_label, instruction);
    // }

    fn next_label(&mut self) -> Self::F {
        self.builder.next_label()
    }

    fn basic_block(&mut self) {
        self.builder.basic_block();
    }

    fn block_label(&mut self) -> B::F {
        self.builder.block_label()
    }

    fn set_current_block(&mut self, label: Self::F) {
        self.builder.set_current_block(label);
    }
}

// impl<'a, B: Builder> CondBuilder<'a, B> {
//     pub fn then<Func>(&mut self, f: Func)
//     where
//         Func: FnOnce(&mut Self),
//     {
//         if self.then_label.is_some() {
//             panic!("execution block already defined for this condition");
//         }
//         // process the conditions and execute the then block
//         let (lhs, rhs) = match (self.lhs, self.rhs) {
//             (Symbolic::Value(lhs), Symbolic::Value(rhs)) => (lhs, rhs),
//             _ => panic!("symbolic values not supported"),
//         };

//         // Execute the then block
//         f(self);

//         // Start the else block
//         self.basic_block();
//         let else_label = self.block_label();
//         // If the condition is not met, jump to the else block.
//         // let instr = AsmInstruction::BEQ(else_label, self.lhs.0, self.rhs.0);
//     }

//     pub fn else_then<Func>(&mut self, f: Func)
//     where
//         Func: FnOnce(&mut Self),
//     {
//         todo!()
//     }
// }

/// A builder for a for loop.
///
/// Starting with end < start will lead to undefined behavior!
pub struct ForBuilder<'a, B: Builder> {
    builder: &'a mut B,
    start: Felt<B::F>,
    end: Felt<B::F>,
    loop_var: Felt<B::F>,
}

impl<'a, B: Builder> Builder for ForBuilder<'a, B> {
    type F = B::F;
    fn get_mem(&mut self, size: usize) -> i32 {
        self.builder.get_mem(size)
    }

    fn push(&mut self, instruction: AsmInstruction<B::F>) {
        self.builder.push(instruction);
    }

    // fn push_to_block(&mut self, block_label: Self::F, instruction: AsmInstruction<Self::F>) {
    //     self.builder.push_to_block(block_label, instruction);
    // }

    fn next_label(&mut self) -> Self::F {
        self.builder.next_label()
    }

    fn basic_block(&mut self) {
        self.builder.basic_block();
    }

    fn block_label(&mut self) -> B::F {
        self.builder.block_label()
    }

    fn set_current_block(&mut self, label: Self::F) {
        self.builder.set_current_block(label);
    }
}

impl<'a, B: Builder> ForBuilder<'a, B> {
    pub fn for_each<Func>(&mut self, f: Func)
    where
        Func: FnOnce(Felt<B::F>, &mut Self),
    {
        // The function block structure:
        // - Setting the loop range
        // - Executing the loop body and incrementing the loop variable
        // - the loop condition
        let initial_block = self.block_label();
        let loop_var = self.loop_var;
        // Set the loop variable to the start of the range.
        self.assign(loop_var, self.start);
        // Jump to the loop condition.
        let j_label = self.next_label();
        println!("Jump label: {:?}", j_label);
        let instr = AsmInstruction::j(j_label, self);
        self.push(instr);

        // Start the loop condition block.
        self.basic_block();
        let loop_body = self.next_label();
        // Jump to loop body if the loop condition still holds.
        let instr = AsmInstruction::BNE(loop_body, loop_var.0, self.end.0);
        self.push(instr);

        // Navigate back to initial block
        self.set_current_block(initial_block);
        // Start the loop condition block.
        self.basic_block();
        // The loop body.
        f(loop_var, self);
        // Increment the loop variable.
        self.assign(loop_var, loop_var + B::F::one());

        // Set the current block to be the loop condition block.
        self.set_current_block(j_label);

        println!("Current block: {:?}", self.block_label());
    }
}
