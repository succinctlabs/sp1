use super::{Config, DslIR, Ext, SymbolicExt, SymbolicFelt, SymbolicUsize, Usize};
use super::{Felt, Var};
use super::{SymbolicVar, Variable};
use alloc::vec::Vec;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;

#[derive(Debug, Clone)]
pub struct Builder<C: Config> {
    pub(crate) felt_count: u32,
    pub(crate) ext_count: u32,
    pub(crate) var_count: u32,
    pub operations: Vec<DslIR<C>>,
}

impl<C: Config> Default for Builder<C> {
    fn default() -> Self {
        Self {
            felt_count: 0,
            ext_count: 0,
            var_count: 0,
            operations: Vec::new(),
        }
    }
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

    pub(crate) fn push(&mut self, op: DslIR<C>) {
        self.operations.push(op);
    }

    pub fn uninit<V: Variable<C>>(&mut self) -> V {
        V::uninit(self)
    }

    pub fn assign<V: Variable<C>, E: Into<V::Expression>>(&mut self, dst: V, expr: E) {
        dst.assign(expr.into(), self);
    }

    pub fn eval<V: Variable<C>, E: Into<V::Expression>>(&mut self, expr: E) -> V {
        let dst = V::uninit(self);
        dst.assign(expr.into(), self);
        dst
    }

    pub fn assert_eq<V: Variable<C>, LhsExpr: Into<V::Expression>, RhsExpr: Into<V::Expression>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        V::assert_eq(lhs, rhs, self);
    }

    pub fn assert_ne<V: Variable<C>, LhsExpr: Into<V::Expression>, RhsExpr: Into<V::Expression>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        V::assert_ne(lhs, rhs, self);
    }

    pub fn assert_var_eq<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Var<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_var_ne<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Var<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_felt_eq<LhsExpr: Into<SymbolicFelt<C::F>>, RhsExpr: Into<SymbolicFelt<C::F>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Felt<C::F>, _, _>(lhs, rhs);
    }

    pub fn assert_felt_ne<LhsExpr: Into<SymbolicFelt<C::F>>, RhsExpr: Into<SymbolicFelt<C::F>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Felt<C::F>, _, _>(lhs, rhs);
    }

    pub fn assert_usize_eq<
        LhsExpr: Into<SymbolicUsize<C::N>>,
        RhsExpr: Into<SymbolicUsize<C::N>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Usize<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_usize_ne(&mut self, lhs: SymbolicUsize<C::N>, rhs: SymbolicUsize<C::N>) {
        self.assert_ne::<Usize<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_ext_eq<
        LhsExpr: Into<SymbolicExt<C::F, C::EF>>,
        RhsExpr: Into<SymbolicExt<C::F, C::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Ext<C::F, C::EF>, _, _>(lhs, rhs);
    }

    pub fn assert_ext_ne<
        LhsExpr: Into<SymbolicExt<C::F, C::EF>>,
        RhsExpr: Into<SymbolicExt<C::F, C::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Ext<C::F, C::EF>, _, _>(lhs, rhs);
    }

    pub fn if_eq<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<C> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: true,
            builder: self,
        }
    }

    pub fn if_ne<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<C> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: false,
            builder: self,
        }
    }

    pub fn range(
        &mut self,
        start: impl Into<Usize<C::N>>,
        end: impl Into<Usize<C::N>>,
    ) -> RangeBuilder<C> {
        RangeBuilder {
            start: start.into(),
            end: end.into(),
            builder: self,
        }
    }

    pub fn print_v(&mut self, dst: Var<C::N>) {
        self.operations.push(DslIR::PrintV(dst));
    }

    pub fn print_f(&mut self, dst: Felt<C::F>) {
        self.operations.push(DslIR::PrintF(dst));
    }

    pub fn print_e(&mut self, dst: Ext<C::F, C::EF>) {
        self.operations.push(DslIR::PrintE(dst));
    }

    pub fn ext_from_base_slice(&mut self, arr: &[Felt<C::F>]) -> Ext<C::F, C::EF> {
        assert_eq!(arr.len(), <C::EF as AbstractExtensionField::<C::F>>::D);
        let mut res = SymbolicExt::Const(C::EF::zero());
        for i in 0..arr.len() {
            res += arr[i] * SymbolicExt::Const(C::EF::monomial(i));
        }
        self.eval(res)
    }
}

pub struct IfBuilder<'a, C: Config> {
    lhs: SymbolicVar<C::N>,
    rhs: SymbolicVar<C::N>,
    is_eq: bool,
    pub(crate) builder: &'a mut Builder<C>,
}

enum Condition<N> {
    EqConst(N, N),
    NeConst(N, N),
    Eq(Var<N>, Var<N>),
    EqI(Var<N>, N),
    Ne(Var<N>, Var<N>),
    NeI(Var<N>, N),
}

impl<'a, C: Config> IfBuilder<'a, C> {
    pub fn then(mut self, mut f: impl FnMut(&mut Builder<C>)) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();

        // Execute the `then`` block and collect the instructions.
        let mut f_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );
        f(&mut f_builder);
        let then_instructions = f_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            Condition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            Condition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            Condition::Eq(lhs, rhs) => {
                let op = DslIR::IfEq(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
            Condition::EqI(lhs, rhs) => {
                let op = DslIR::IfEqI(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
            Condition::Ne(lhs, rhs) => {
                let op = DslIR::IfNe(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
            Condition::NeI(lhs, rhs) => {
                let op = DslIR::IfNeI(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
        }
    }

    pub fn then_or_else(
        mut self,
        mut then_f: impl FnMut(&mut Builder<C>),
        mut else_f: impl FnMut(&mut Builder<C>),
    ) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();
        let mut then_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        // Execute the `then` and `else_then` blocks and collect the instructions.
        then_f(&mut then_builder);
        let then_instructions = then_builder.operations;

        let mut else_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );
        else_f(&mut else_builder);
        let else_instructions = else_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            Condition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            Condition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            Condition::Eq(lhs, rhs) => {
                let op = DslIR::IfEq(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            Condition::EqI(lhs, rhs) => {
                let op = DslIR::IfEqI(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            Condition::Ne(lhs, rhs) => {
                let op = DslIR::IfNe(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            Condition::NeI(lhs, rhs) => {
                let op = DslIR::IfNeI(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
        }
    }

    fn condition(&mut self) -> Condition<C::N> {
        match (self.lhs.clone(), self.rhs.clone(), self.is_eq) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs), true) => {
                Condition::EqConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs), false) => {
                Condition::NeConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs), true) => Condition::EqI(rhs, lhs),
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs), false) => Condition::NeI(rhs, lhs),
            (SymbolicVar::Const(lhs), rhs, true) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::EqI(rhs, lhs)
            }
            (SymbolicVar::Const(lhs), rhs, false) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::NeI(rhs, lhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::EqI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::NeI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::EqI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::NeI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs), true) => Condition::Eq(lhs, rhs),
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs), false) => Condition::Ne(lhs, rhs),
            (SymbolicVar::Val(lhs), rhs, true) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Eq(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), rhs, false) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Ne(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::Eq(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::Ne(lhs, rhs)
            }
            (lhs, rhs, true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Eq(lhs, rhs)
            }
            (lhs, rhs, false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Ne(lhs, rhs)
            }
        }
    }
}

pub struct RangeBuilder<'a, C: Config> {
    start: Usize<C::N>,
    end: Usize<C::N>,
    builder: &'a mut Builder<C>,
}

impl<'a, C: Config> RangeBuilder<'a, C> {
    pub fn for_each(self, mut f: impl FnMut(Var<C::N>, &mut Builder<C>)) {
        let loop_variable: Var<C::N> = self.builder.uninit();
        let mut loop_body_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        f(loop_variable, &mut loop_body_builder);

        let loop_instructions = loop_body_builder.operations;

        let op = DslIR::For(self.start, self.end, loop_variable, loop_instructions);
        self.builder.operations.push(op);
    }
}
