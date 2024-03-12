use super::Variable;
use super::{Config, DslIR, Expression, Usize};
use super::{Equal, Var};
use alloc::vec::Vec;

#[derive(Debug, Clone, Default)]
pub struct Builder<C: Config> {
    pub(crate) felt_count: u32,
    pub(crate) ext_count: u32,
    pub(crate) var_count: u32,
    pub(crate) operations: Vec<DslIR<C>>,
}

impl<C: Config> Builder<C> {
    pub fn new(var_count: u32, felt_count: u32, ext_count: u32) -> Self {
        Self {
            felt_count,
            ext_count,
            var_count,
            operations: Vec::new(),
        }
    }

    pub fn uninit<V: Variable<C>>(&mut self) -> V {
        V::uninit(self)
    }

    pub fn assign<E: Expression<C>>(&mut self, dst: E::Value, expr: E) {
        expr.assign(dst, self);
    }

    pub fn assert_eq<Lhs, Rhs>(&mut self, lhs: Lhs, rhs: Rhs)
    where
        Lhs: Equal<C, Rhs>,
    {
        lhs.assert_equal(&rhs, self);
    }

    pub fn if_(&mut self, condition: Var<C>) -> IfBuilder<C> {
        IfBuilder {
            condition,
            builder: self,
        }
    }

    pub fn range(&mut self, start: Usize<C>, end: Usize<C>) -> RangeBuilder<C> {
        RangeBuilder {
            start,
            end,
            builder: self,
        }
    }
}

pub struct IfBuilder<'a, C: Config> {
    condition: Var<C>,
    pub(crate) builder: &'a mut Builder<C>,
}

impl<'a, C: Config> IfBuilder<'a, C> {
    pub fn then(self, f: impl FnOnce(&mut Builder<C>)) {
        let mut f_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        f(&mut f_builder);

        let then_instructions = f_builder.operations;

        let op = DslIR::If(self.condition, then_instructions, Vec::new());
        self.builder.operations.push(op);
    }

    pub fn then_or_else(
        self,
        then_f: impl FnOnce(&mut Builder<C>),
        else_f: impl FnOnce(&mut Builder<C>),
    ) {
        let mut then_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        then_f(&mut then_builder);
        let then_instructions = then_builder.operations;

        let mut else_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        else_f(&mut else_builder);
        let else_instructions = else_builder.operations;

        let op = DslIR::If(self.condition, then_instructions, else_instructions);
        self.builder.operations.push(op);
    }
}

pub struct RangeBuilder<'a, C: Config> {
    start: Usize<C>,
    end: Usize<C>,
    builder: &'a mut Builder<C>,
}

impl<'a, C: Config> RangeBuilder<'a, C> {
    pub fn for_each(self, f: impl FnOnce(Var<C>, &mut Builder<C>)) {
        let loop_variable: Var<C> = self.builder.uninit();
        let mut loop_body_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        f(loop_variable, &mut loop_body_builder);

        let loop_instructions = loop_body_builder.operations;

        let op = DslIR::For(self.start, self.end, loop_instructions);
        self.builder.operations.push(op);
    }
}
